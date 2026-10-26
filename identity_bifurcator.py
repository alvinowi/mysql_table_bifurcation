#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Identity Bifurcation Tool
=========================
Single-file Tkinter GUI for MySQL.

What it does
------------
* Connects to a MySQL server with a full connection string.
* Lets you pick a table and tick the identity (PII) columns to hide.
* Generates a *new* database that stores one UUID per source row plus the
  original identity values and metadata (source schema/table/columns,
  row hash, created_at, updated_at).
* The source table is NEVER altered, updated or dropped.
* Produces re-runnable, transactional SQL, exports it per project, runs it
  from the app, and can browse the resulting "bifurcated" view.

Requires: Python 3.9+ (Tkinter included) and PyMySQL.
    python -m pip install pymysql
"""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import math
import os
import queue
import re
import sys
import threading
import traceback
import uuid
import zipfile
from dataclasses import dataclass, field
from decimal import Decimal
from urllib.parse import parse_qsl, quote, unquote, urlsplit

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_NAME = "Identity Bifurcation Tool"
APP_VERSION = "1.2.0"
PROJECT_SUFFIX = ".idb.json"
DEFAULT_CHARSET = "utf8mb4"

try:
    import pymysql
    from pymysql.cursors import DictCursor
except Exception as _exc:  # pragma: no cover - environment check
    _r = tk.Tk()
    _r.withdraw()
    messagebox.showerror(
        "PyMySQL is required",
        "This tool needs the pure-Python MySQL driver PyMySQL.\n\n"
        "Open a terminal and run:\n\n    python -m pip install pymysql\n\n"
        f"Details: {_exc}",
    )
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

META_UUID = "_identity_uuid"
META_HASH = "_row_hash"
META_SOURCE_SCHEMA = "_source_schema"
META_SOURCE_TABLE = "_source_table"
META_SOURCE_COLUMNS = "_source_columns"
META_CREATED = "_created_at"
META_UPDATED = "_updated_at"

META_COLUMNS = {
    META_UUID, META_HASH, META_SOURCE_SCHEMA, META_SOURCE_TABLE,
    META_SOURCE_COLUMNS, META_CREATED, META_UPDATED,
}

IDENT_NAME_RE = re.compile(r"^[A-Za-z0-9_$]{1,64}$")

PII_HINTS = (
    "nama", "name", "nik", "ktp", "npwp", "sim", "passport", "paspor", "kitas",
    "phone", "telp", "telepon", "hp", "wa", "whatsapp", "msisdn",
    "email", "mail", "alamat", "address", "addr", "domisili",
    "birth", "lahir", "dob", "tgl_lahir", "tanggal_lahir",
    "rekening", "account", "acct", "card", "kartu", "credit",
    "ibu", "mother", "kk", "keluarga", "gender", "agama", "religion",
)

NULL_HASH_TOKEN = "<NULL>"
HASH_SEPARATOR = "CHAR(31)"


# ---------------------------------------------------------------------------
# Connection strings
# ---------------------------------------------------------------------------

class DsnError(ValueError):
    pass


_KEY_ALIASES = {
    "host": "host", "server": "host", "hostname": "host", "data source": "host",
    "address": "host", "addr": "host",
    "port": "port",
    "user": "user", "uid": "user", "username": "user", "user id": "user",
    "userid": "user",
    "password": "password", "pwd": "password", "pass": "password",
    "database": "database", "db": "database", "dbname": "database",
    "initial catalog": "database", "schema": "database",
    "charset": "charset", "charsetname": "charset", "character set": "charset",
}


def parse_dsn(dsn: str) -> dict:
    """Parse mysql://user:pass@host:3306/db?charset=utf8mb4 or key=value form."""
    raw = (dsn or "").strip()
    if not raw:
        raise DsnError("Connection string is empty.")

    if "://" in raw:
        parts = urlsplit(raw)
        scheme = (parts.scheme or "").split("+")[0].lower()
        if scheme != "mysql":
            raise DsnError(
                f"Unsupported scheme '{parts.scheme}'. Expected mysql://user:password@host:3306/database"
            )
        try:
            port = parts.port or 3306
        except ValueError as exc:
            raise DsnError(f"Invalid port in connection string: {exc}") from exc
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        return {
            "host": parts.hostname or "127.0.0.1",
            "port": int(port),
            "user": unquote(parts.username or ""),
            "password": unquote(parts.password or ""),
            "database": unquote((parts.path or "").lstrip("/")),
            "charset": params.get("charset") or params.get("charsetname") or DEFAULT_CHARSET,
        }

    if "=" in raw:
        found: dict[str, str] = {}
        for chunk in raw.split(";"):
            if not chunk.strip():
                continue
            if "=" not in chunk:
                raise DsnError(f"Cannot parse segment '{chunk.strip()}'. Use key=value pairs.")
            key, _, value = chunk.partition("=")
            key = key.strip().lower()
            value = value.strip().strip("'\"")
            target = _KEY_ALIASES.get(key)
            if target:
                found[target] = value
        if not found.get("host") and not found.get("database"):
            raise DsnError("Connection string needs at least host=... (and usually database=...).")
        try:
            port = int(found.get("port") or 3306)
        except ValueError as exc:
            raise DsnError(f"Invalid port '{found.get('port')}'.") from exc
        return {
            "host": found.get("host") or "127.0.0.1",
            "port": port,
            "user": found.get("user", ""),
            "password": found.get("password", ""),
            "database": found.get("database", ""),
            "charset": found.get("charset") or DEFAULT_CHARSET,
        }

    # shorthand: user:password@host:3306/database
    m = re.match(r"^(?P<user>[^:@/]*)(?::(?P<pw>[^@/]*))?@(?P<host>[^:/]+)(?::(?P<port>\d+))?(?:/(?P<db>.+))?$", raw)
    if m:
        return {
            "host": m.group("host"),
            "port": int(m.group("port") or 3306),
            "user": m.group("user") or "",
            "password": m.group("pw") or "",
            "database": (m.group("db") or "").strip(),
            "charset": DEFAULT_CHARSET,
        }

    raise DsnError(
        "Unrecognised connection string. Use one of:\n"
        "  mysql://user:password@host:3306/database\n"
        "  host=localhost;port=3306;user=root;password=secret;database=mydb"
    )


def build_dsn(host: str, port=3306, user: str = "", password: str = "",
              database: str = "", charset: str = DEFAULT_CHARSET,
              style: str = "url") -> str:
    """Compose a connection string from individual fields."""
    host = (host or "").strip()
    for prefix in ("mysql://", "mariadb://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix):]
    host = host.strip().strip("/")
    if not host:
        raise DsnError("Server address is required.")
    try:
        port = int(str(port).strip() or 3306)
    except (TypeError, ValueError) as exc:
        raise DsnError(f"Port must be a number (got '{port}').") from exc
    if not 1 <= port <= 65535:
        raise DsnError("Port must be between 1 and 65535.")
    charset = (charset or DEFAULT_CHARSET).strip() or DEFAULT_CHARSET
    user = (user or "").strip()
    database = (database or "").strip()

    if style == "keyvalue":
        return (f"host={host};port={port};user={user};password={password};"
                f"database={database};charset={charset}")

    credentials = quote(user, safe="")
    if password:
        credentials += ":" + quote(password, safe="")
    return (f"mysql://{credentials}@{host}:{port}/"
            f"{quote(database, safe='')}?charset={charset}")


def dsn_summary(dsn: str) -> str:
    try:
        p = parse_dsn(dsn)
    except DsnError as exc:
        return f"Unparsed: {exc}"
    pw = "password set" if p["password"] else "no password"
    db = p["database"] or "(server only)"
    return f"{p['user'] or '(no user)'}@{p['host']}:{p['port']} / {db} / {pw}"


def dsn_without_password(dsn: str) -> str:
    """Rebuild a DSN without the password so it is safe to store in a project."""
    try:
        p = parse_dsn(dsn)
    except DsnError:
        return dsn
    if not p["password"]:
        return dsn
    user = quote(p["user"], safe="")
    db = quote(p["database"], safe="")
    host = p["host"]
    return f"mysql://{user}@{host}:{p['port']}/{db}?charset={p['charset']}"


# ---------------------------------------------------------------------------
# SQL helpers
# ---------------------------------------------------------------------------

def sql_ident(name: str) -> str:
    return "`" + str(name).replace("`", "``") + "`"


def sql_str(value: str) -> str:
    s = str(value).replace("\\", "\\\\").replace("'", "''")
    return "'" + s + "'"


def fq(db: str, name: str) -> str:
    return f"{sql_ident(db)}.{sql_ident(name)}"


def comment_line(text: str) -> str:
    return "-- " + str(text).replace("\r", " ").replace("\n", " ")


def _only_comments(stmt: str) -> bool:
    s = re.sub(r"/\*.*?\*/", " ", stmt, flags=re.S)
    s = re.sub(r"(?m)^\s*(--|#).*$", " ", s)
    return not s.strip()


def split_sql_script(text: str) -> list[str]:
    """Split a MySQL script into statements, honouring DELIMITER, quotes, comments."""
    stmts: list[str] = []
    buf: list[str] = []
    delim = ";"
    i, n = 0, len(text)
    at_start = True

    def flush() -> None:
        stmt = "".join(buf).strip()
        if stmt and not _only_comments(stmt):
            stmts.append(stmt)

    while i < n:
        ch = text[i]

        if ch in " \t\r\n":
            buf.append(ch)
            i += 1
            continue

        if (text.startswith("--", i) and (i + 2 >= n or text[i + 2] in " \t\r\n")) or ch == "#":
            j = text.find("\n", i)
            j = n if j == -1 else j
            buf.append(text[i:j])
            i = j
            continue

        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            buf.append(text[i:j])
            i = j
            continue

        if at_start and text[i:i + 9].upper() == "DELIMITER":
            j = text.find("\n", i)
            j = n if j == -1 else j
            line = text[i:j].strip()
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[1].strip():
                delim = parts[1].strip()
                buf.clear()
                i = j + 1 if j < n else n
                continue

        at_start = False

        if ch in "'\"`":
            quote_ch = ch
            buf.append(ch)
            i += 1
            while i < n:
                c2 = text[i]
                buf.append(c2)
                if c2 == "\\" and quote_ch != "`" and i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    continue
                if c2 == quote_ch:
                    if i + 1 < n and text[i + 1] == quote_ch:
                        buf.append(text[i + 1])
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue

        if text.startswith(delim, i):
            flush()
            buf = []
            i += len(delim)
            at_start = True
            continue

        buf.append(ch)
        i += 1

    flush()
    return stmts


def guarded_ddl(check_from: str, ddl: str) -> str:
    """Emit idempotent DDL using information_schema + PREPARE."""
    return (
        "SET @idb_ddl := (SELECT IF(COUNT(*) = 0,\n"
        f"  {sql_str(ddl)},\n"
        "  'SELECT 1')\n"
        f" FROM {check_from});\n"
        "PREPARE idb_stmt FROM @idb_ddl;\n"
        "EXECUTE idb_stmt;\n"
        "DEALLOCATE PREPARE idb_stmt;"
    )


def format_result_sets(sets, row_limit: int = 60) -> str:
    """Render pymysql result sets as plain aligned text for the log pane."""
    chunks: list[str] = []
    for _rowcount, cols, rows in sets:
        if not cols:
            continue
        header = list(cols)
        body: list[list[str]] = []
        for row in rows[:row_limit]:
            body.append(["" if row.get(c) is None else str(row.get(c)) for c in header])
        widths = []
        for idx, name in enumerate(header):
            w = len(name)
            for line in body:
                w = max(w, len(line[idx]))
            widths.append(min(max(w, 3), 42))
        sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
        out = [sep, "| " + " | ".join(header[i][:widths[i]].ljust(widths[i]) for i in range(len(header))) + " |", sep]
        for line in body:
            out.append("| " + " | ".join(line[i][:widths[i]].ljust(widths[i]) for i in range(len(header))) + " |")
        out.append(sep)
        if len(rows) > row_limit:
            out.append(f"... {len(rows) - row_limit} more row(s)")
        chunks.append("\n".join(out))
    return "\n".join(chunks)


def cell_text(value, limit: int = 200) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bytes>"
    text = str(value).replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def is_pii_name(name: str) -> bool:
    low = name.lower()
    return any(h in low for h in PII_HINTS)


def short_hash(text: str, size: int = 8) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:size]


# ---------------------------------------------------------------------------
# Project model
# ---------------------------------------------------------------------------

@dataclass
class Options:
    same_server: bool = True
    identity_dsn: str = ""
    identity_db: str = ""
    skip_empty: bool = True
    delete_stale: bool = False
    make_pseudonymized_view: bool = True
    use_proc: bool = True
    include_secrets: bool = False


@dataclass
class Mapping:
    source_schema: str
    source_table: str
    pk_columns: list[str] = field(default_factory=list)
    identity_columns: list[str] = field(default_factory=list)
    identity_table: str = ""
    view_name: str = ""
    pseudo_view_name: str = ""
    columns: list[dict] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.source_schema}.{self.source_table}"

    def column(self, name: str) -> dict | None:
        for col in self.columns:
            if col.get("name") == name:
                return col
        return None

    def to_dict(self) -> dict:
        return {
            "source_schema": self.source_schema,
            "source_table": self.source_table,
            "pk_columns": list(self.pk_columns),
            "identity_columns": list(self.identity_columns),
            "identity_table": self.identity_table,
            "view_name": self.view_name,
            "pseudo_view_name": self.pseudo_view_name,
            "columns": [dict(c) for c in self.columns],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Mapping":
        return cls(
            source_schema=data.get("source_schema", ""),
            source_table=data.get("source_table", ""),
            pk_columns=list(data.get("pk_columns") or []),
            identity_columns=list(data.get("identity_columns") or []),
            identity_table=data.get("identity_table", ""),
            view_name=data.get("view_name", ""),
            pseudo_view_name=data.get("pseudo_view_name", ""),
            columns=list(data.get("columns") or []),
        )


@dataclass
class Project:
    name: str = "Untitled project"
    source_dsn: str = ""
    options: Options = field(default_factory=Options)
    mappings: list[Mapping] = field(default_factory=list)

    def mapping_for(self, schema: str, table: str) -> Mapping | None:
        for m in self.mappings:
            if m.source_schema == schema and m.source_table == table:
                return m
        return None

    def to_dict(self, include_secrets: bool = False) -> dict:
        src = self.source_dsn if include_secrets else dsn_without_password(self.source_dsn)
        idn = self.options.identity_dsn
        if not include_secrets:
            idn = dsn_without_password(idn)
        return {
            "app": "identity-bifurcator",
            "version": 1,
            "name": self.name,
            "source_dsn": src,
            "options": {
                "same_server": self.options.same_server,
                "identity_dsn": idn,
                "identity_db": self.options.identity_db,
                "skip_empty": self.options.skip_empty,
                "delete_stale": self.options.delete_stale,
                "make_pseudonymized_view": self.options.make_pseudonymized_view,
                "use_proc": self.options.use_proc,
                "include_secrets": include_secrets,
            },
            "mappings": [m.to_dict() for m in self.mappings],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Project":
        opts = data.get("options") or {}
        return cls(
            name=data.get("name") or "Untitled project",
            source_dsn=data.get("source_dsn") or "",
            options=Options(
                same_server=bool(opts.get("same_server", True)),
                identity_dsn=opts.get("identity_dsn") or "",
                identity_db=opts.get("identity_db") or "",
                skip_empty=bool(opts.get("skip_empty", True)),
                delete_stale=bool(opts.get("delete_stale", False)),
                make_pseudonymized_view=bool(opts.get("make_pseudonymized_view", True)),
                use_proc=bool(opts.get("use_proc", True)),
                include_secrets=bool(opts.get("include_secrets", False)),
            ),
            mappings=[Mapping.from_dict(m) for m in (data.get("mappings") or [])],
        )


def demo_project() -> Project:
    cols = [
        {"name": "id", "column_type": "bigint unsigned", "data_type": "bigint",
         "is_nullable": "NO", "charset": None, "collation": None, "ordinal": 1},
        {"name": "full_name", "column_type": "varchar(120)", "data_type": "varchar",
         "is_nullable": "YES", "charset": "utf8mb4", "collation": "utf8mb4_general_ci", "ordinal": 2},
        {"name": "nik", "column_type": "varchar(16)", "data_type": "varchar",
         "is_nullable": "YES", "charset": "utf8mb4", "collation": "utf8mb4_general_ci", "ordinal": 3},
        {"name": "email", "column_type": "varchar(190)", "data_type": "varchar",
         "is_nullable": "YES", "charset": "utf8mb4", "collation": "utf8mb4_general_ci", "ordinal": 4},
        {"name": "phone", "column_type": "varchar(32)", "data_type": "varchar",
         "is_nullable": "YES", "charset": "utf8mb4", "collation": "utf8mb4_general_ci", "ordinal": 5},
        {"name": "city", "column_type": "varchar(80)", "data_type": "varchar",
         "is_nullable": "YES", "charset": "utf8mb4", "collation": "utf8mb4_general_ci", "ordinal": 6},
        {"name": "created_at", "column_type": "datetime", "data_type": "datetime",
         "is_nullable": "YES", "charset": None, "collation": None, "ordinal": 7},
    ]
    return Project(
        name="Demo - customers PII",
        source_dsn="mysql://app_user@127.0.0.1:3306/crm?charset=utf8mb4",
        options=Options(same_server=True, identity_db="crm_identity"),
        mappings=[
            Mapping(
                source_schema="crm",
                source_table="customers",
                pk_columns=["id"],
                identity_columns=["full_name", "nik", "email", "phone"],
                identity_table="ident_customers",
                view_name="v_customers_bifurcated",
                pseudo_view_name="v_customers_pseudonymized",
                columns=cols,
            )
        ],
    )


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------

def clip_ident(name: str, suffix: str = "") -> str:
    """Make an identifier <= 64 chars, keeping a short hash when truncating."""
    name = re.sub(r"[^A-Za-z0-9_$]", "_", name or "")
    if not name:
        name = "obj"
    if name[0].isdigit():
        name = "n_" + name
    extra = suffix
    if len(name + extra) > 64:
        room = 64 - len(extra) - 9
        name = name[: max(room, 1)] + "_" + short_hash(name, 8)
    return name + extra


def default_identity_table(table: str) -> str:
    return clip_ident("ident_" + table)


def default_view_name(table: str) -> str:
    return clip_ident("v_" + table + "_bifurcated")


def default_pseudo_view_name(table: str) -> str:
    return clip_ident("v_" + table + "_pseudonymized")


def plan_column_names(mapping: Mapping):
    """Return (link_columns, identity_columns) as lists of (source, target, colinfo)."""
    used: set[str] = set(META_COLUMNS)
    links: list[tuple[str, str, dict]] = []

    for pk in mapping.pk_columns:
        col = mapping.column(pk) or {"name": pk, "column_type": "varchar(255)"}
        target = clip_ident("_src_" + pk)
        base = target
        counter = 1
        while target in used:
            target = clip_ident(base[: 60] + f"_{counter}")
            counter += 1
        used.add(target)
        links.append((pk, target, col))

    idents: list[tuple[str, str, dict]] = []
    for name in mapping.identity_columns:
        col = mapping.column(name) or {"name": name, "column_type": "varchar(255)"}
        target = name
        if target in used:
            target = clip_ident(name + "__idt")
        counter = 1
        while target in used:
            target = clip_ident(name[: 55] + f"_{counter}_idt")
            counter += 1
        used.add(target)
        idents.append((name, target, col))

    return links, idents


def source_columns_to_view_prefix(mapping: Mapping) -> str:
    prefix = "idf_"
    existing = {c.get("name", "") for c in mapping.columns}
    while any(name.startswith(prefix) for name in existing):
        prefix = "_" + prefix
    return prefix


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_project(project: Project) -> list[str]:
    errors: list[str] = []
    opts = project.options

    if not opts.identity_db:
        errors.append("Identity database name is required.")
    elif not IDENT_NAME_RE.match(opts.identity_db):
        errors.append("Identity database name must be 1-64 chars of A-Z, a-z, 0-9, _ or $.")

    if not project.mappings:
        errors.append("Add at least one table mapping in step 2 (Choose columns).")

    for m in project.mappings:
        label = m.key
        if not m.pk_columns:
            errors.append(f"{label}: no primary key selected (required to link identity rows).")
        if not m.identity_columns:
            errors.append(f"{label}: tick at least one identity column.")
        if not m.identity_table or not IDENT_NAME_RE.match(m.identity_table):
            errors.append(f"{label}: invalid identity table name '{m.identity_table}'.")
        if m.view_name and not IDENT_NAME_RE.match(m.view_name):
            errors.append(f"{label}: invalid view name '{m.view_name}'.")
        if m.pseudo_view_name and not IDENT_NAME_RE.match(m.pseudo_view_name):
            errors.append(f"{label}: invalid pseudonymized view name '{m.pseudo_view_name}'.")
        if m.identity_table and m.identity_table == m.source_table and m.source_schema == opts.identity_db:
            errors.append(f"{label}: identity table would overwrite the source table.")
        if m.identity_table.lower() == m.source_table.lower() and opts.identity_db.lower() == m.source_schema.lower():
            errors.append(f"{label}: identity table would overwrite the source table.")
        if m.source_schema == opts.identity_db:
            errors.append(f"{label}: identity database must differ from the source database '{m.source_schema}'.")

    names: dict[str, str] = {}
    views: dict[str, str] = {}
    for m in project.mappings:
        low = m.identity_table.lower()
        if low in names:
            errors.append(f"Identity table '{m.identity_table}' is used by more than one mapping.")
        names[low] = m.key
        candidates = [m.view_name]
        if project.options.make_pseudonymized_view:
            candidates.append(m.pseudo_view_name)
        for view in candidates:
            if not view:
                continue
            if view.lower() in views:
                errors.append(f"View '{view}' is used by more than one mapping.")
            views[view.lower()] = m.key
    return errors


def plan_warnings(project: Project) -> list[str]:
    warnings: list[str] = []
    opts = project.options
    if opts.same_server:
        warnings.append("Same server: a view is created in the identity database that joins back to the source table.")
    else:
        warnings.append("Separate servers: no SQL view can join both sides. Data is pushed by the app in batches; "
                        "browsing uses an in-app merge. The identity server must support the source column "
                        "characters sets and collations.")
    for m in project.mappings:
        if m.pseudo_view_name and project.options.make_pseudonymized_view:
            hidden = set(m.identity_columns)
            kept = [c for c in m.columns if c.get("name") and c.get("name") not in hidden]
            if not kept:
                warnings.append(f"{m.key}: every column is hidden as identity data, so no pseudonymized view "
                                "will be created.")
        sizes = []
        for pk in m.pk_columns:
            col = m.column(pk) or {}
            ct = (col.get("column_type") or "").lower()
            mm = re.match(r"(?:var)?char\((\d+)\)", ct)
            if mm:
                sizes.append(int(mm.group(1)) * 4)
        if sizes and sum(sizes) > 3000:
            warnings.append(f"{m.key}: primary key is wide; the unique index on the identity table may exceed "
                            "InnoDB's 3072-byte limit.")
        for name in m.identity_columns:
            col = m.column(name) or {}
            if "blob" in (col.get("column_type") or "").lower() or "binary" in (col.get("data_type") or "").lower():
                warnings.append(f"{m.key}.{name}: binary column will be stored as-is and hashed via CAST AS CHAR.")
        if (m.column(m.pk_columns[0]) or {}).get("is_nullable") == "YES":
            warnings.append(f"{m.key}: primary key column is nullable, which is unusual for a real PK.")
    if not opts.delete_stale:
        warnings.append("Stale identity rows (source row deleted) are kept. Enable cleanup in step 4 (Run) if wanted.")
    return warnings


# ---------------------------------------------------------------------------
# SQL generation
# ---------------------------------------------------------------------------

@dataclass
class MappingSQL:
    mapping: Mapping
    ddl: list[str]
    load: list[str]
    views: list[str]
    verify: str
    links: list[tuple[str, str, dict]]
    idents: list[tuple[str, str, dict]]


@dataclass
class Plan:
    project: Project
    create_db: str
    mapping_sqls: list[MappingSQL]
    warnings: list[str]
    cross_server: bool
    verify_sql: str
    script_text: str

    def ddl_statements(self) -> list[str]:
        out: list[str] = []
        for item in [self.create_db] + [s for ms in self.mapping_sqls for s in ms.ddl]:
            out.extend(split_sql_script(item))
        return out

    def objects(self) -> list[tuple[str, str, str, str]]:
        """(kind, name, database, note) for the review table."""
        p = self.project
        out = [("database", p.options.identity_db, p.options.identity_db, "created if missing")]
        for ms in self.mapping_sqls:
            m = ms.mapping
            out.append(("table", m.identity_table, p.options.identity_db,
                        f"{len(ms.idents)} identity column(s) + UUID"))
            if self.cross_server:
                out.append(("data load", m.key, p.options.identity_db, "streamed by the app"))
            else:
                if m.view_name:
                    out.append(("view", m.view_name, p.options.identity_db, "bifurcated join"))
                if p.options.make_pseudonymized_view and m.pseudo_view_name:
                    out.append(("view", m.pseudo_view_name, p.options.identity_db, "PII columns removed"))
        return out


def coldef(col: dict, name: str, not_null: bool = False) -> str:
    column_type = col.get("column_type") or col.get("data_type") or "varchar(255)"
    out = f"{sql_ident(name)} {column_type}"
    charset = col.get("charset")
    collation = col.get("collation")
    if charset and collation:
        out += f" CHARACTER SET {charset} COLLATE {collation}"
    out += " NOT NULL" if not_null else " NULL"
    return out


def _identity_table_columns(mapping: Mapping, links, idents) -> list[str]:
    lines = [f"  {coldef({'column_type': 'char(36)'}, META_UUID, True)}"]
    for _src, target, col in links:
        lines.append(f"  {coldef(col, target, True)}")
    for _src, target, col in idents:
        lines.append(f"  {coldef(col, target, False)}")
    lines.append(f"  {coldef({'column_type': 'char(64)'}, META_HASH, True)}")
    lines.append(f"  {coldef({'column_type': 'varchar(64)'}, META_SOURCE_SCHEMA, True)}")
    lines.append(f"  {coldef({'column_type': 'varchar(64)'}, META_SOURCE_TABLE, True)}")
    lines.append(f"  {coldef({'column_type': 'text'}, META_SOURCE_COLUMNS, True)}")
    lines.append(f"  {coldef({'column_type': 'datetime'}, META_CREATED, True)} DEFAULT CURRENT_TIMESTAMP")
    lines.append(f"  {coldef({'column_type': 'datetime'}, META_UPDATED, True)} DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP")
    lines.append(f"  PRIMARY KEY ({sql_ident(META_UUID)})")
    lines.append(f"  UNIQUE KEY {sql_ident('uq_source_row')} ({', '.join(sql_ident(t) for _s, t, _c in links)})")
    return lines


def _join_on(alias_ident: str, alias_src: str, links) -> str:
    return " AND ".join(f"{alias_ident}.{sql_ident(t)} = {alias_src}.{sql_ident(s)}" for s, t, _c in links)


def _hash_expr(alias_src: str, idents) -> str:
    parts = [f"IFNULL(CAST({alias_src}.{sql_ident(src)} AS CHAR), '{NULL_HASH_TOKEN}')" for src, _t, _c in idents]
    return f"SHA2(CONCAT_WS({HASH_SEPARATOR}, " + ", ".join(parts) + "), 256)"


def _not_empty_expr(alias_src: str, idents) -> str:
    parts = [f"COALESCE(TRIM(CAST({alias_src}.{sql_ident(src)} AS CHAR)), '') <> ''" for src, _t, _c in idents]
    return "(" + " OR ".join(parts) + ")"


def _pii_column_list(mapping: Mapping) -> str:
    return ",".join(mapping.identity_columns)


def build_mapping_sql(project: Project, mapping: Mapping) -> MappingSQL:
    opts = project.options
    idb = opts.identity_db
    itbl = mapping.identity_table
    links, idents = plan_column_names(mapping)

    ddl = [
        f"CREATE TABLE IF NOT EXISTS {fq(idb, itbl)} (\n"
        + ",\n".join(_identity_table_columns(mapping, links, idents))
        + "\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
    ]

    for _src, target, col in links:
        ddl.append(guarded_ddl(
            f"information_schema.COLUMNS WHERE TABLE_SCHEMA = {sql_str(idb)} "
            f"AND TABLE_NAME = {sql_str(itbl)} AND COLUMN_NAME = {sql_str(target)}",
            f"ALTER TABLE {fq(idb, itbl)} ADD COLUMN {coldef(col, target, True)}",
        ))
    for _src, target, col in idents:
        ddl.append(guarded_ddl(
            f"information_schema.COLUMNS WHERE TABLE_SCHEMA = {sql_str(idb)} "
            f"AND TABLE_NAME = {sql_str(itbl)} AND COLUMN_NAME = {sql_str(target)}",
            f"ALTER TABLE {fq(idb, itbl)} ADD COLUMN {coldef(col, target, False)}",
        ))
    ddl.append(guarded_ddl(
        f"information_schema.STATISTICS WHERE TABLE_SCHEMA = {sql_str(idb)} "
        f"AND TABLE_NAME = {sql_str(itbl)} AND INDEX_NAME = {sql_str('uq_source_row')}",
        f"ALTER TABLE {fq(idb, itbl)} ADD UNIQUE KEY {sql_ident('uq_source_row')} "
        f"({', '.join(sql_ident(t) for _s, t, _c in links)})",
    ))

    join_on = _join_on("i", "s", links)
    hash_expr = _hash_expr("s", idents)
    not_empty = _not_empty_expr("s", idents)
    src_fq = fq(mapping.source_schema, mapping.source_table)
    dst_fq = fq(idb, itbl)
    pii_csv = _pii_column_list(mapping)

    set_parts = [f"i.{sql_ident(t)} = s.{sql_ident(src)}" for src, t, _c in idents]
    set_parts.append(f"i.{sql_ident(META_HASH)} = {hash_expr}")
    set_parts.append(f"i.{sql_ident(META_SOURCE_COLUMNS)} = {sql_str(pii_csv)}")
    set_parts.append(f"i.{sql_ident(META_UPDATED)} = NOW()")

    update_sql = (
        f"UPDATE {dst_fq} i\n"
        f"JOIN {src_fq} s ON {join_on}\n"
        f"SET " + ",\n    ".join(set_parts) + "\n"
        f"WHERE i.{sql_ident(META_HASH)} <> {hash_expr}"
    )
    if opts.skip_empty:
        update_sql += f"\n  AND {not_empty}"

    insert_cols = [META_UUID] + [t for _s, t, _c in links] + [t for _s, t, _c in idents] + [
        META_HASH, META_SOURCE_SCHEMA, META_SOURCE_TABLE, META_SOURCE_COLUMNS, META_CREATED,
    ]
    select_parts = ["UUID()"] + [f"s.{sql_ident(s)}" for s, _t, _c in links]
    select_parts += [f"s.{sql_ident(s)}" for s, _t, _c in idents]
    select_parts += [
        hash_expr,
        sql_str(mapping.source_schema),
        sql_str(mapping.source_table),
        sql_str(pii_csv),
        "NOW()",
    ]
    insert_sql = (
        f"INSERT INTO {dst_fq} (\n  " + ", ".join(sql_ident(c) for c in insert_cols) + "\n)\n"
        "SELECT\n  " + ",\n  ".join(select_parts) + "\n"
        f"FROM {src_fq} s\n"
        f"LEFT JOIN {dst_fq} i ON {join_on}\n"
        f"WHERE i.{sql_ident(META_UUID)} IS NULL"
    )
    if opts.skip_empty:
        insert_sql += f"\n  AND {not_empty}"

    load = [update_sql, insert_sql]

    if opts.delete_stale:
        first_pk = sql_ident(mapping.pk_columns[0])
        delete_sql = (
            f"DELETE i FROM {dst_fq} i\n"
            f"LEFT JOIN {src_fq} s ON {join_on}\n"
            f"WHERE s.{first_pk} IS NULL"
        )
        load.append(delete_sql)

    views: list[str] = []
    if not project.options.same_server:
        views = []
    else:
        prefix = source_columns_to_view_prefix(mapping)
        extra = [f"i.{sql_ident(META_UUID)} AS {sql_ident(prefix + 'uuid')}"]
        for _src, target, _c in idents:
            extra.append(f"i.{sql_ident(target)} AS {sql_ident(prefix + target)}")
        extra.append(f"i.{sql_ident(META_CREATED)} AS {sql_ident(prefix + 'created_at')}")
        extra.append(f"i.{sql_ident(META_UPDATED)} AS {sql_ident(prefix + 'updated_at')}")
        if mapping.view_name:
            views.append(
                f"CREATE OR REPLACE VIEW {fq(idb, mapping.view_name)} AS\n"
                f"SELECT s.*,\n  " + ",\n  ".join(extra) + "\n"
                f"FROM {src_fq} s\n"
                f"LEFT JOIN {dst_fq} i ON {join_on};"
            )
        if project.options.make_pseudonymized_view and mapping.pseudo_view_name:
            hidden = set(mapping.identity_columns)
            kept = [c.get("name", "") for c in mapping.columns if c.get("name") and c.get("name") not in hidden]
            if kept:
                sel = ",\n  ".join(f"s.{sql_ident(c)}" for c in kept)
                sel += f",\n  i.{sql_ident(META_UUID)} AS {sql_ident(prefix + 'uuid')}"
                sel += f",\n  i.{sql_ident(META_CREATED)} AS {sql_ident(prefix + 'created_at')}"
                views.append(
                    f"CREATE OR REPLACE VIEW {fq(idb, mapping.pseudo_view_name)} AS\n"
                    f"SELECT\n  {sel}\n"
                    f"FROM {src_fq} s\n"
                    f"LEFT JOIN {dst_fq} i ON {join_on};"
                )

    first_link = sql_ident(links[0][1])
    verify = (
        f"SELECT {sql_str(mapping.key)} AS `mapping`,\n"
        f"  (SELECT COUNT(*) FROM {src_fq}) AS `source_rows`,\n"
        f"  (SELECT COUNT(*) FROM {dst_fq}) AS `identity_rows`,\n"
        f"  (SELECT COUNT(*) FROM {src_fq} s LEFT JOIN {dst_fq} i ON {join_on}\n"
        f"     WHERE i.{sql_ident(META_UUID)} IS NULL) AS `rows_without_identity`,\n"
        f"  (SELECT COUNT(*) FROM {dst_fq} i LEFT JOIN {src_fq} s ON {join_on}\n"
        f"     WHERE s.{sql_ident(mapping.pk_columns[0])} IS NULL) AS `orphan_identity_rows`"
    )

    return MappingSQL(mapping=mapping, ddl=ddl, load=load, views=views, verify=verify,
                      links=links, idents=idents)


def proc_name(mapping: Mapping) -> str:
    return clip_ident("_idb_load_" + mapping.source_schema + "_" + mapping.source_table)


def wrap_transaction(project: Project, ms: MappingSQL) -> str:
    mapping = ms.mapping
    if not project.options.use_proc:
        body = "START TRANSACTION;\n" + "\n".join(s + ";" for s in ms.load) + "\nCOMMIT;"
        return body

    name = proc_name(mapping)
    idb = project.options.identity_db
    body = "\n".join("  " + s.replace("\n", "\n  ") + ";" for s in ms.load)
    return (
        f"DROP PROCEDURE IF EXISTS {fq(idb, name)};\n"
        "DELIMITER $$\n"
        f"CREATE PROCEDURE {fq(idb, name)}()\n"
        "BEGIN\n"
        "  DECLARE EXIT HANDLER FOR SQLEXCEPTION\n"
        "  BEGIN\n"
        "    ROLLBACK;\n"
        "    RESIGNAL;\n"
        "  END;\n"
        "  START TRANSACTION;\n"
        f"{body}\n"
        "  COMMIT;\n"
        "END$$\n"
        "DELIMITER ;\n"
        f"CALL {fq(idb, name)}();\n"
        f"DROP PROCEDURE IF EXISTS {fq(idb, name)};"
    )


def build_plan(project: Project, use_proc: bool | None = None) -> Plan:
    if use_proc is not None:
        project.options.use_proc = use_proc
    opts = project.options
    cross = not opts.same_server
    create_db = (
        f"CREATE DATABASE IF NOT EXISTS {sql_ident(opts.identity_db)} "
        "DEFAULT CHARACTER SET utf8mb4;"
    )

    mapping_sqls = [build_mapping_sql(project, m) for m in project.mappings]
    warnings = plan_warnings(project)

    verifies: list[str]
    if cross:
        verifies = [
            f"SELECT {sql_str(m.key)} AS `mapping`,\n"
            f"  (SELECT COUNT(*) FROM {fq(opts.identity_db, m.identity_table)}) AS `identity_rows`"
            for m in project.mappings
        ]
    else:
        verifies = [ms.verify for ms in mapping_sqls]
    verify_sql = "\nUNION ALL\n".join(verifies)

    header = [
        "-- " + "=" * 72,
        comment_line(f"{APP_NAME} {APP_VERSION} - project: {project.name}"),
        comment_line(f"Generated: {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"),
        comment_line(f"Source server : {dsn_without_password(project.source_dsn)}"),
        comment_line(f"Identity DB   : {opts.identity_db}"),
        comment_line(f"Mode          : {'separate servers (client-side load)' if cross else 'same server'}"),
        "--",
        "-- SOURCE TABLES ARE NOT MODIFIED. All writes go to the identity database.",
        "-- Re-runnable: CREATE IF NOT EXISTS + guarded ALTERs + idempotent DML.",
        "-- DML is wrapped in a transaction (rolled back on error).",
        "-- " + "=" * 72,
        "",
    ]
    parts = ["\n".join(header), create_db, ""]

    for ms in mapping_sqls:
        m = ms.mapping
        parts.append(comment_line(f"Mapping: {m.key}  ->  {opts.identity_db}.{m.identity_table}"))
        parts.append("")
        parts.extend(ms.ddl)
        parts.append("")
        if cross:
            parts.append(comment_line(
                "DATA LOAD: identity DB is on another server, so rows are streamed by the app. "
                "Run the migration from step 4 (Run)."))
            parts.append("")
        else:
            parts.append(comment_line("DATA LOAD (transactional, idempotent)"))
            parts.append(wrap_transaction(project, ms))
            parts.append("")
            if ms.views:
                parts.append(comment_line("VIEWS (browse / export)"))
                parts.extend(ms.views)
                parts.append("")

    parts.append(comment_line("VERIFICATION"))
    parts.append(verify_sql + ";")
    parts.append("")

    script = "\n".join(parts)
    return Plan(project=project, create_db=create_db, mapping_sqls=mapping_sqls,
                warnings=warnings, cross_server=cross, verify_sql=verify_sql,
                script_text=script)


# ---------------------------------------------------------------------------
# Database access
# ---------------------------------------------------------------------------

RECONNECT_CODES = (2006, 2013, 2055)


class Db:
    def __init__(self, dsn: str = ""):
        self.dsn = dsn
        self.params: dict | None = None
        self.conn = None
        self.server_version = ""
        self.ignore_database = False
        self.default_database = ""

    def configure(self, dsn: str) -> None:
        params = parse_dsn(dsn)
        self.close()
        self.dsn = dsn
        self.params = params

    def use(self, database: str) -> None:
        self._ensure()
        with self.conn.cursor() as cur:
            cur.execute("USE " + sql_ident(database))
        self.default_database = database

    def close(self) -> None:
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
        self.conn = None

    @property
    def connected(self) -> bool:
        return self.conn is not None and getattr(self.conn, "open", False)

    def connect(self):
        if not self.params:
            self.configure(self.dsn)
        p = self.params or {}
        self.conn = pymysql.connect(
            host=p.get("host") or "127.0.0.1",
            port=int(p.get("port") or 3306),
            user=p.get("user") or "",
            password=p.get("password") or "",
            database=None if self.ignore_database else (p.get("database") or None),
            charset=p.get("charset") or DEFAULT_CHARSET,
            cursorclass=DictCursor,
            autocommit=True,
            connect_timeout=15,
            read_timeout=600,
            write_timeout=600,
        )
        try:
            self.server_version = self.conn.get_server_info()
        except Exception:
            self.server_version = ""
        if self.default_database:
            try:
                with self.conn.cursor() as cur:
                    cur.execute("USE " + sql_ident(self.default_database))
            except Exception:
                self.default_database = ""
        return self

    def _ensure(self) -> None:
        if not self.connected:
            self.connect()

    def _run(self, fn):
        last_exc = None
        for attempt in (0, 1):
            try:
                self._ensure()
                return fn()
            except pymysql.err.OperationalError as exc:
                last_exc = exc
                code = exc.args[0] if exc.args else None
                if attempt == 0 and code in RECONNECT_CODES:
                    self.close()
                    continue
                raise
        raise last_exc  # pragma: no cover

    def exec_multi(self, sql: str, args=None):
        def go():
            out = []
            with self.conn.cursor() as cur:
                cur.execute(sql, args)
                while True:
                    rowcount = cur.rowcount
                    if cur.description:
                        cols = [d[0] for d in cur.description]
                        rows = cur.fetchall()
                    else:
                        cols, rows = [], []
                    out.append((rowcount, cols, rows))
                    if not cur.nextset():
                        break
            return out
        return self._run(go)

    def run(self, sql: str, args=None) -> int:
        sets = self.exec_multi(sql, args)
        return sets[0][0] if sets else 0

    def q(self, sql: str, args=None) -> list[dict]:
        for _rc, cols, rows in self.exec_multi(sql, args):
            if cols:
                return rows
        return []

    def scalar(self, sql: str, args=None):
        rows = self.q(sql, args)
        if not rows:
            return None
        return next(iter(rows[0].values()))

    def describe(self, sql: str) -> list[str]:
        def go():
            with self.conn.cursor() as cur:
                cur.execute(sql)
                return [d[0] for d in (cur.description or [])]
        return self._run(go)

    # -- introspection -----------------------------------------------------

    def list_databases(self) -> list[str]:
        rows = self.q("SHOW DATABASES")
        names = [str(v) for row in rows for v in row.values()]
        system = {"information_schema", "mysql", "performance_schema", "sys"}
        return sorted(names, key=lambda n: (n.lower() in system, n.lower()))

    def list_tables(self, schema: str) -> list[dict]:
        rows = self.q(
            "SELECT TABLE_NAME AS name, ENGINE AS engine, TABLE_ROWS AS rows_est, "
            "TABLE_TYPE AS ttype FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA = %s AND TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME",
            (schema,),
        )
        return [dict(r) for r in rows]

    def table_columns(self, schema: str, table: str) -> list[dict]:
        rows = self.q(
            "SELECT COLUMN_NAME, DATA_TYPE, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY, EXTRA, "
            "CHARACTER_SET_NAME, COLLATION_NAME, ORDINAL_POSITION, COLUMN_COMMENT "
            "FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s "
            "ORDER BY ORDINAL_POSITION",
            (schema, table),
        )
        out = []
        for r in rows:
            out.append({
                "name": r["COLUMN_NAME"],
                "data_type": (r["DATA_TYPE"] or "").lower(),
                "column_type": r["COLUMN_TYPE"] or "",
                "is_nullable": r["IS_NULLABLE"] or "YES",
                "key": r["COLUMN_KEY"] or "",
                "extra": r["EXTRA"] or "",
                "charset": r["CHARACTER_SET_NAME"],
                "collation": r["COLLATION_NAME"],
                "ordinal": r["ORDINAL_POSITION"],
                "comment": r["COLUMN_COMMENT"] or "",
            })
        return out

    def primary_key(self, schema: str, table: str) -> list[str]:
        rows = self.q(
            "SELECT COLUMN_NAME FROM information_schema.STATISTICS "
            "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND INDEX_NAME = 'PRIMARY' "
            "ORDER BY SEQ_IN_INDEX",
            (schema, table),
        )
        return [r["COLUMN_NAME"] for r in rows]

    def table_exists(self, schema: str, table: str) -> bool:
        try:
            return bool(self.scalar(
                "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s",
                (schema, table),
            ))
        except Exception:
            return False

    def samples(self, schema: str, table: str, columns: list[str], limit: int = 200) -> dict:
        if not columns:
            return {}
        col_sql = ", ".join(sql_ident(c) for c in columns)
        rows = self.q(f"SELECT {col_sql} FROM {fq(schema, table)} LIMIT {int(limit)}")
        out: dict[str, list[str]] = {c: [] for c in columns}
        for row in rows:
            for c in columns:
                value = cell_text(row.get(c), 40)
                if value not in ("NULL", "") and value not in out[c] and len(out[c]) < 3:
                    out[c].append(value)
        return out


def _version_tuple(version: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", version or "")
    return tuple(int(n) for n in nums[:3]) if nums else (0,)


def py_row_hash(values) -> str:
    parts = []
    for value in values:
        if value is None:
            parts.append(NULL_HASH_TOKEN)
        elif isinstance(value, (bytes, bytearray)):
            parts.append(bytes(value).decode("utf-8", "replace"))
        elif isinstance(value, (dt.datetime, dt.date, dt.time)):
            parts.append(str(value))
        else:
            parts.append(str(value))
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def execute_plan(plan: Plan, src_db: Db, dst_db: Db, emit, progress=None) -> None:
    """Run the plan. Same server: whole script on the source connection.
    Separate servers: DDL on the identity server + client-side streaming."""
    p = plan.project
    if plan.cross_server:
        ddl = plan.ddl_statements()
        for idx, stmt in enumerate(ddl, 1):
            emit("sql", _one_line(stmt))
            src_db is not None  # keep reference explicit
            dst_db.exec_multi(stmt)
            if progress:
                progress(idx, len(ddl) + len(plan.mapping_sqls))
        try:
            dst_db.use(p.options.identity_db)
        except Exception:
            pass
        for idx, ms in enumerate(plan.mapping_sqls, 1):
            load_mapping_cross_server(plan, ms, src_db, dst_db, emit)
            if progress:
                progress(len(ddl) + idx, len(ddl) + len(plan.mapping_sqls))
        verify_cross_server(plan, src_db, dst_db, emit)
        return

    stmts = split_sql_script(plan.script_text)
    total = len(stmts)
    for idx, stmt in enumerate(stmts, 1):
        emit("sql", _one_line(stmt))
        sets = src_db.exec_multi(stmt)
        if progress:
            progress(idx, total)
        rendered = format_result_sets(sets)
        if rendered:
            emit("result", rendered)
        elif sets and sets[0][0] and sets[0][0] > 0:
            emit("ok", f"{sets[0][0]} row(s) affected")


def _one_line(stmt: str, limit: int = 150) -> str:
    first = stmt.strip().splitlines()[0] if stmt.strip() else ""
    return first if len(first) <= limit else first[: limit - 3] + "..."


def _fetch_batch(src_db: Db, mapping: Mapping, links, idents, last_key, size: int) -> list[dict]:
    cols = [sql_ident(s) for s, _t, _c in links] + [sql_ident(s) for s, _t, _c in idents]
    sql = f"SELECT {', '.join(cols)} FROM {fq(mapping.source_schema, mapping.source_table)}"
    args = []
    if last_key is not None:
        if len(links) == 1:
            sql += f" WHERE {sql_ident(links[0][0])} > %s"
        else:
            sql += " WHERE (" + ", ".join(sql_ident(s) for s, _t, _c in links) + ") > (" + \
                   ", ".join(["%s"] * len(links)) + ")"
        args.extend(list(last_key))
    order = ", ".join(sql_ident(s) for s, _t, _c in links)
    sql += f" ORDER BY {order} LIMIT {int(size)}"
    return src_db.q(sql, tuple(args) if args else None)


def _upsert_sql(plan: Plan, ms: MappingSQL, batch_len: int, version: tuple[int, ...]) -> tuple[str, list[str]]:
    idb = plan.project.options.identity_db
    m = ms.mapping
    cols = [META_UUID] + [t for _s, t, _c in ms.links] + [t for _s, t, _c in ms.idents] + [
        META_HASH, META_SOURCE_SCHEMA, META_SOURCE_TABLE, META_SOURCE_COLUMNS, META_CREATED,
    ]
    row_ph = "(" + ", ".join(["%s"] * len(cols)) + ")"
    values = ", ".join([row_ph] * batch_len)
    if isinstance(version, tuple):
        vt, is_maria = version, False
    else:
        vt = _version_tuple(str(version))
        is_maria = "mariadb" in str(version).lower()
    alias = (not is_maria) and vt >= (8, 0, 19)
    ref = "new_row" if alias else None
    updates = []
    if alias:
        updates.append(f"{sql_ident(META_UPDATED)} = IF({sql_ident(META_HASH)} <> new_row.{sql_ident(META_HASH)}, NOW(), {sql_ident(META_UPDATED)})")
    else:
        updates.append(f"{sql_ident(META_UPDATED)} = IF({sql_ident(META_HASH)} <> VALUES({sql_ident(META_HASH)}), NOW(), {sql_ident(META_UPDATED)})")
    for _s, target, _c in ms.idents:
        src_ref = f"new_row.{sql_ident(target)}" if alias else f"VALUES({sql_ident(target)})"
        updates.append(f"{sql_ident(target)} = {src_ref}")
    hash_ref = f"new_row.{sql_ident(META_HASH)}" if alias else f"VALUES({sql_ident(META_HASH)})"
    updates.append(f"{sql_ident(META_HASH)} = {hash_ref}")
    updates.append(f"{sql_ident(META_SOURCE_COLUMNS)} = {sql_str(_pii_column_list(m))}")
    tail = (" AS new_row" if alias else "")
    sql = (
        f"INSERT INTO {fq(idb, m.identity_table)} ({', '.join(sql_ident(c) for c in cols)})\n"
        f"VALUES {values}{tail}\n"
        "ON DUPLICATE KEY UPDATE\n  " + ",\n  ".join(updates)
    )
    return sql, cols


def load_mapping_cross_server(plan: Plan, ms: MappingSQL, src_db: Db, dst_db: Db, emit) -> None:
    m = ms.mapping
    p = plan.project
    batch_size = 200
    emit("info", f"Loading {m.key} -> {p.options.identity_db}.{m.identity_table} (client-side)")
    ncols = 1 + len(ms.links) + len(ms.idents) + 5
    upsert_cache: dict[int, str] = {}

    def upsert_for(count: int) -> str:
        sql = upsert_cache.get(count)
        if sql is None:
            sql, _cols = _upsert_sql(plan, ms, count, dst_db.server_version)
            upsert_cache[count] = sql
        return sql

    source_total = int(src_db.scalar(f"SELECT COUNT(*) FROM {fq(m.source_schema, m.source_table)}") or 0)
    emit("info", f"{source_total} source row(s) to inspect")

    last_key = None
    loaded = 0
    touched = 0
    dst_db.run("START TRANSACTION")
    try:
        while True:
            batch = _fetch_batch(src_db, m, ms.links, ms.idents, last_key, batch_size)
            if not batch:
                break
            params = []
            for row in batch:
                loaded += 1
                ident_values = [row.get(src) for src, _t, _c in ms.idents]
                if p.options.skip_empty and all(
                    v is None or str(v).strip() == "" for v in ident_values
                ):
                    last_key = tuple(row.get(s) for s, _t, _c in ms.links)
                    continue
                params.append(str(uuid.uuid4()))
                for s, _t, _c in ms.links:
                    params.append(row.get(s))
                for s, _t, _c in ms.idents:
                    params.append(row.get(s))
                params.append(py_row_hash(ident_values))
                params.append(m.source_schema)
                params.append(m.source_table)
                params.append(_pii_column_list(m))
                params.append(dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                last_key = tuple(row.get(s) for s, _t, _c in ms.links)
            rows_in_payload = len(params) // ncols
            if rows_in_payload:
                dst_db.run(upsert_for(rows_in_payload), tuple(params))
                touched += rows_in_payload
            emit("progress", f"{loaded}/{source_total} read, {touched} written")
        if p.options.delete_stale:
            _delete_stale_cross_server(plan, ms, src_db, dst_db, emit)
        dst_db.run("COMMIT")
    except Exception:
        try:
            dst_db.run("ROLLBACK")
        except Exception:
            pass
        raise
    emit("ok", f"{m.key}: {touched} identity row(s) written")


def _delete_stale_cross_server(plan: Plan, ms: MappingSQL, src_db: Db, dst_db: Db, emit) -> None:
    m = ms.mapping
    p = plan.project
    emit("info", "Removing identity rows whose source row no longer exists")
    seen = fq(p.options.identity_db, "_idb_seen")
    dst_db.run(f"DROP TEMPORARY TABLE IF EXISTS {seen}")
    defs = []
    for _s, t, c in ms.links:
        item = f"{sql_ident(t)} {c.get('column_type') or 'varchar(255)'}"
        if c.get("charset") and c.get("collation"):
            item += f" CHARACTER SET {c['charset']} COLLATE {c['collation']}"
        defs.append(item + " NOT NULL")
    dst_db.run(f"CREATE TEMPORARY TABLE {seen} ({', '.join(defs)}) ENGINE=InnoDB")
    placeholders = "(" + ", ".join(["%s"] * len(ms.links)) + ")"
    last_key = None
    while True:
        batch = _fetch_batch(src_db, m, ms.links, [], last_key, 500)
        if not batch:
            break
        params = []
        for row in batch:
            params.extend([row.get(s) for s, _t, _c in ms.links])
            last_key = tuple(row.get(s) for s, _t, _c in ms.links)
        dst_db.run(
            f"INSERT INTO {seen} VALUES " + ", ".join([placeholders] * len(batch)),
            tuple(params),
        )
    join = _join_on("i", "t", [(t, t, c) for _s, t, c in ms.links])
    deleted = dst_db.run(
        f"DELETE i FROM {fq(p.options.identity_db, m.identity_table)} i "
        f"LEFT JOIN {seen} t ON {join} WHERE t.{sql_ident(ms.links[0][1])} IS NULL"
    )
    dst_db.run(f"DROP TEMPORARY TABLE IF EXISTS {seen}")
    emit("ok", f"{deleted} stale identity row(s) removed")


def verify_cross_server(plan: Plan, src_db: Db, dst_db: Db, emit) -> None:
    p = plan.project
    rows = []
    for ms in plan.mapping_sqls:
        m = ms.mapping
        src_count = int(src_db.scalar(f"SELECT COUNT(*) FROM {fq(m.source_schema, m.source_table)}") or 0)
        dst_count = int(dst_db.scalar(f"SELECT COUNT(*) FROM {fq(p.options.identity_db, m.identity_table)}") or 0)
        rows.append({"mapping": m.key, "source_rows": src_count, "identity_rows": dst_count})
    if rows:
        cols = ["mapping", "source_rows", "identity_rows"]
        width = [max(len(c), *(len(str(r[c])) for r in rows)) for c in cols]
        line = "+" + "+".join("-" * (w + 2) for w in width) + "+"
        out = [line, "| " + " | ".join(cols[i].ljust(width[i]) for i in range(len(cols))) + " |", line]
        for r in rows:
            out.append("| " + " | ".join(str(r[cols[i]]).ljust(width[i]) for i in range(len(cols))) + " |")
        out.append(line)
        emit("result", "\n".join(out))


# ---------------------------------------------------------------------------
# Page export helpers (CSV / XLSX / SQL INSERT)
# ---------------------------------------------------------------------------

_XLSX_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_XLSX_MAX_CELL = 32767

_XLSX_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>"""

_XLSX_ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

_XLSX_WORKBOOK_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""

_XLSX_STYLES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<numFmts count="2">
<numFmt numFmtId="164" formatCode="yyyy-mm-dd hh:mm:ss"/>
<numFmt numFmtId="165" formatCode="yyyy-mm-dd"/>
</numFmts>
<fonts count="2">
<font><sz val="11"/><color theme="1"/><name val="Calibri"/><family val="2"/></font>
<font><b/><sz val="11"/><color theme="1"/><name val="Calibri"/><family val="2"/></font>
</fonts>
<fills count="2">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
</fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="4">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>
<xf numFmtId="165" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"""

_XLSX_EPOCH = dt.datetime(1899, 12, 30)


def _xlsx_serial(value) -> float:
    if isinstance(value, dt.datetime):
        moment = value.replace(tzinfo=None)
    else:
        moment = dt.datetime.combine(value, dt.time())
    return (moment - _XLSX_EPOCH).total_seconds() / 86400.0


def xlsx_column_letter(index: int) -> str:
    """1 -> A, 26 -> Z, 27 -> AA."""
    letters = ""
    while index > 0:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters or "A"


def _xml_text(value) -> str:
    text = _XLSX_ILLEGAL.sub("", str(value))[:_XLSX_MAX_CELL]
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _xlsx_cell(ref: str, value, style: int | None = None) -> str:
    if value is None:
        return ""
    style_attr = f' s="{style}"' if style else ""
    if isinstance(value, bool):
        return f'<c r="{ref}" t="b"{style_attr}><v>{1 if value else 0}</v></c>'
    if isinstance(value, Decimal):
        if value.is_nan() or value.is_infinite():
            text = _xml_text(value)
            return f'<c r="{ref}" t="inlineStr"{style_attr}><is><t>{text}</t></is></c>'
        number = format(value, "f")
        return f'<c r="{ref}"{style_attr}><v>{number}</v></c>'
    if isinstance(value, int):
        return f'<c r="{ref}"{style_attr}><v>{value}</v></c>'
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return f'<c r="{ref}" t="inlineStr"{style_attr}><is><t>{value}</t></is></c>'
        return f'<c r="{ref}"{style_attr}><v>{repr(value)}</v></c>'
    if isinstance(value, dt.datetime):
        return f'<c r="{ref}" s="{style or 2}"><v>{repr(_xlsx_serial(value))}</v></c>'
    if isinstance(value, dt.date):
        return f'<c r="{ref}" s="{style or 3}"><v>{repr(_xlsx_serial(value))}</v></c>'
    if isinstance(value, (bytes, bytearray)):
        if not value:
            return ""
        shown = "0x" + bytes(value).hex()
        if len(shown) > 4000:
            shown = shown[:4000] + f"... ({len(value)} bytes)"
    else:
        shown = str(value)
    return (f'<c r="{ref}" t="inlineStr"{style_attr}><is><t xml:space="preserve">'
            f"{_xml_text(shown)}</t></is></c>")


def write_xlsx_page(path: str, sheet_name: str, columns: list[str], rows: list[dict]) -> None:
    """Write a minimal, dependency-free .xlsx workbook with one sheet."""
    sheet = re.sub(r"[\[\]:*?/\\']", "_", sheet_name or "Page").strip() or "Page"
    sheet = sheet[:31]

    widths: list[int] = []
    for name in columns:
        longest = len(str(name))
        for row in rows[:200]:
            longest = max(longest, len(cell_text(row.get(name), 80)))
        widths.append(min(max(longest + 2, 10), 60))
    cols_xml = "<cols>" + "".join(
        f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>'
        for i, w in enumerate(widths, 1)
    ) + "</cols>"

    body: list[str] = []
    header_cells = "".join(
        _xlsx_cell(f"{xlsx_column_letter(index)}1", name, 1)
        for index, name in enumerate(columns, 1)
    )
    body.append(f'<row r="1">{header_cells}</row>')
    for row_number, row in enumerate(rows, 2):
        cells = []
        for index, name in enumerate(columns, 1):
            cell = _xlsx_cell(f"{xlsx_column_letter(index)}{row_number}", row.get(name))
            if cell:
                cells.append(cell)
        body.append(f'<row r="{row_number}">{"".join(cells)}</row>')

    worksheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        "</sheetView></sheetViews>"
        + cols_xml
        + "<sheetData>" + "".join(body) + "</sheetData></worksheet>"
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets><sheet name="{_xml_text(sheet)}" sheetId="1" r:id="rId1"/></sheets>'
        "</workbook>"
    )

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _XLSX_CONTENT_TYPES)
        archive.writestr("_rels/.rels", _XLSX_ROOT_RELS)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", _XLSX_WORKBOOK_RELS)
        archive.writestr("xl/styles.xml", _XLSX_STYLES)
        archive.writestr("xl/worksheets/sheet1.xml", worksheet)


def _mysql_quote(text: str) -> str:
    chunks = ["'"]
    for char in text:
        if char == "\\":
            chunks.append("\\\\")
        elif char == "'":
            chunks.append("''")
        elif char == "\0":
            chunks.append("\\0")
        elif char == "\n":
            chunks.append("\\n")
        elif char == "\r":
            chunks.append("\\r")
        elif ord(char) == 26:
            chunks.append("\\Z")
        else:
            chunks.append(char)
    chunks.append("'")
    return "".join(chunks)


def sql_literal(value) -> str:
    """Render one Python value as a MySQL literal."""
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Decimal):
        if value.is_nan() or value.is_infinite():
            return "NULL"
        return format(value, "f")
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return "NULL"
        return repr(value)
    if isinstance(value, (bytes, bytearray)):
        return "X'" + bytes(value).hex() + "'"
    if isinstance(value, dt.datetime):
        return "'" + value.strftime("%Y-%m-%d %H:%M:%S") + "'"
    if isinstance(value, dt.date):
        return "'" + value.isoformat() + "'"
    if isinstance(value, dt.time):
        return "'" + value.isoformat() + "'"
    return _mysql_quote(str(value))


def build_insert_script(target: str, columns: list[str], rows: list[dict],
                        header: list[str], chunk_size: int = 100) -> str:
    lines = [comment_line(item) for item in header]
    lines.append("")
    lines.append("SET NAMES utf8mb4;")
    lines.append("START TRANSACTION;")
    lines.append("")
    column_sql = ", ".join(sql_ident(name) for name in columns)
    for start in range(0, len(rows), chunk_size):
        chunk = rows[start:start + chunk_size]
        lines.append(f"INSERT INTO {target} (")
        lines.append("  " + column_sql)
        lines.append(") VALUES")
        values = []
        for row in chunk:
            rendered = ", ".join(sql_literal(row.get(name)) for name in columns)
            values.append(f"  ({rendered})")
        lines.append(",\n".join(values) + ";")
        lines.append("")
    lines.append("COMMIT;")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

TAG_COLORS = {
    "info": ("#333333", None),
    "ok": ("#0b6b2f", None),
    "warn": ("#8a5a00", None),
    "err": ("#a11b1b", None),
    "sql": ("#1b4f9c", None),
    "result": ("#222222", "#f3f5f8"),
    "muted": ("#6b6b6b", None),
}

WIZARD_STEPS = [
    (
        "Connect",
        "Paste a MySQL connection string, or build one from server address, user and "
        "password. Then press Test & connect.",
    ),
    (
        "Choose columns",
        "Pick a source table, tick the identity columns to hide and press "
        "Add / update mapping. Tables without a primary key cannot be used.",
    ),
    (
        "Review",
        "Check what will be created, read the warnings and export the SQL script if you "
        "want to run it somewhere else.",
    ),
    (
        "Run",
        "Run the migration. The source table is never modified - all writes go to the "
        "new identity database.",
    ),
    (
        "Browse",
        "Inspect the joined view and export the page to CSV, Excel or SQL INSERT.",
    ),
]

SIDEBAR_BG = "#f4f7fc"
SIDEBAR_CURRENT_BG = "#dbe9ff"
SIDEBAR_DONE_BG = "#e9f6ed"
SIDEBAR_FG = "#243b53"
SIDEBAR_MUTED = "#8996a8"
BANNER_BG = "#eaf2ff"
BANNER_FG = "#123c7a"
BANNER_SUB = "#3d5680"


class StepStack(ttk.Frame):
    """Minimal stack of step pages with a Notebook-like select() API.

    The wizard drives navigation with its own sidebar and buttons, so the native
    notebook tab strip is not needed.
    """

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self._pages: list[tk.Widget] = []
        self._current: tk.Widget | None = None

    def add(self, page: tk.Widget, text: str = "") -> None:
        self._pages.append(page)
        if self._current is None:
            self.select(page)

    def pages(self) -> list[tk.Widget]:
        return list(self._pages)

    def select(self, page=None):
        if page is None:
            return self._current
        target = page if isinstance(page, tk.Misc) else self.nametowidget(str(page))
        if target not in self._pages:
            return self._current
        if target is self._current:
            return target
        if self._current is not None:
            self._current.pack_forget()
        target.pack(fill="both", expand=True)
        self._current = target
        self.event_generate("<<StepChanged>>")
        return target



class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("1280x840")
        self.minsize(1080, 700)
        self._init_state()
        self._init_style()
        self._build_menu()
        self._build_layout()
        self.after(80, self._poll_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -- state -------------------------------------------------------------

    def _init_state(self) -> None:
        self.project = Project()
        self.src_db = Db()
        self.id_db = Db()
        self.plan: Plan | None = None
        self.busy = False
        self.ui_queue: queue.Queue = queue.Queue()
        self.connected = False
        self.tables_cache: dict[str, list[dict]] = {}
        self.columns_cache: dict[tuple[str, str], list[dict]] = {}
        self.pk_cache: dict[tuple[str, str], list[str]] = {}
        self.samples_cache: dict[tuple[str, str], dict] = {}
        self.ticked: set[str] = set()
        self.current_schema = ""
        self.current_table = ""
        self.current_columns: list[dict] = []
        self.browse_rows: list[dict] = []
        self.browse_cols: list[str] = []
        self.browse_page = 0
        self.browse_total = 0
        self.project_path: str | None = None
        self._detail_token = 0
        self._pending_mapping: Mapping | None = None
        self.max_step = 0
        self.migration_ran = False
        self._advance_after_connect = False
        self._advance_after_identity = False
        self._wizard_syncing = False

        self.var_project = tk.StringVar(value=self.project.name)
        self.var_source_dsn = tk.StringVar()
        self.var_remote = tk.BooleanVar(value=False)
        self.var_ident_dsn = tk.StringVar()
        self.var_identity_db = tk.StringVar(value="")
        self.var_db = tk.StringVar()
        self.var_table_filter = tk.StringVar()
        self.var_col_filter = tk.StringVar()
        self.var_ident_table = tk.StringVar()
        self.var_view = tk.StringVar()
        self.var_pseudo_view = tk.StringVar()
        self.var_skip_empty = tk.BooleanVar(value=True)
        self.var_delete_stale = tk.BooleanVar(value=False)
        self.var_pseudo_on = tk.BooleanVar(value=True)
        self.var_use_proc = tk.BooleanVar(value=True)
        self.var_include_secrets = tk.BooleanVar(value=False)
        self.var_status = tk.StringVar(value="Ready")
        self.var_conn_state = tk.StringVar(value="Not connected")
        self.var_source_summary = tk.StringVar(value="")
        self.var_ident_summary = tk.StringVar(value="")
        self.var_browse_dataset = tk.StringVar(value="Bifurcated view")
        self.var_browse_mapping = tk.StringVar()
        self.var_browse_filter = tk.StringVar()
        self.var_page_size = tk.StringVar(value="50")
        self.var_browse_info = tk.StringVar(value="Not loaded")
        self.var_page_label = tk.StringVar(value="Page 1")
        self.var_table_count = tk.StringVar(value="")

    def _init_style(self) -> None:
        style = ttk.Style(self)
        for theme in ("vista", "clam", "default"):
            if theme in style.theme_names():
                style.theme_use(theme)
                break
        style.configure("Title.TLabel", font=("Segoe UI Semibold", 15))
        style.configure("Sub.TLabel", font=("Segoe UI", 9), foreground="#555555")
        style.configure("Section.TLabel", font=("Segoe UI Semibold", 10))
        style.configure("Mono.TLabel", font=("Consolas", 9))
        style.configure("Treeview", rowheight=21)
        style.configure("Accent.TButton", font=("Segoe UI Semibold", 9))

    # -- async plumbing ----------------------------------------------------

    def _poll_queue(self) -> None:
        try:
            while True:
                callback = self.ui_queue.get_nowait()
                try:
                    callback()
                except Exception:
                    traceback.print_exc()
        except queue.Empty:
            pass
        self.after(80, self._poll_queue)

    def post(self, fn) -> None:
        self.ui_queue.put(fn)

    def run_async(self, label, work, on_done=None, on_error=None) -> None:
        if self.busy:
            messagebox.showinfo("Busy", "Another operation is still running. Please wait.")
            return
        self.set_busy(True, label)

        def runner():
            try:
                result = work()
            except Exception as exc:
                tb = traceback.format_exc()
                self.post(lambda: self.set_busy(False))
                self.post(lambda e=exc, t=tb: self._async_error(e, t, on_error))
            else:
                self.post(lambda: self.set_busy(False))
                self.post(lambda: self._async_done(result, on_done))

        threading.Thread(target=runner, daemon=True).start()

    def _async_done(self, result, on_done) -> None:
        if on_done:
            try:
                on_done(result)
            except Exception:
                self.show_error("Unexpected error", "The operation finished but the result could not be displayed.",
                                traceback.format_exc())

    def _async_error(self, exc, tb, on_error) -> None:
        self._advance_after_connect = False
        self._advance_after_identity = False
        if on_error:
            on_error(exc)
            return
        self.show_error("Operation failed", str(exc), tb)

    def set_busy(self, busy: bool, label: str = "") -> None:
        self.busy = busy
        if busy:
            self.var_status.set(label or "Working...")
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
            self.configure(cursor="watch")
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate", value=0)
            self.configure(cursor="")
            if self.var_status.get() != "Ready":
                self.var_status.set("Ready")

    def show_error(self, title: str, message: str, detail: str = "") -> None:
        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.transient(self)
        dlg.geometry("760x420")
        dlg.columnconfigure(0, weight=1)
        dlg.rowconfigure(1, weight=1)
        ttk.Label(dlg, text=message, wraplength=720, padding=12).grid(row=0, column=0, sticky="w")
        txt = tk.Text(dlg, wrap="none", font=("Consolas", 9))
        txt.grid(row=1, column=0, sticky="nsew", padx=12)
        txt.insert("1.0", detail or message)
        txt.configure(state="disabled")
        btns = ttk.Frame(dlg, padding=10)
        btns.grid(row=2, column=0, sticky="e")

        def copy():
            self.clipboard_clear()
            self.clipboard_append(detail or message)

        ttk.Button(btns, text="Copy details", command=copy).pack(side="left", padx=4)
        ttk.Button(btns, text="Close", command=dlg.destroy).pack(side="left")
        dlg.grab_set()

    # -- menu --------------------------------------------------------------

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New project", accelerator="Ctrl+N", command=self.new_project)
        file_menu.add_command(label="Open project...", accelerator="Ctrl+O", command=self.open_project)
        file_menu.add_command(label="Save project", accelerator="Ctrl+S", command=self.save_project)
        file_menu.add_command(label="Save project as...", command=self.save_project_as)
        file_menu.add_separator()
        file_menu.add_command(label="Export SQL script...", command=self.export_script)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        tools = tk.Menu(menubar, tearoff=0)
        tools.add_command(label="Connection string builder...",
                          command=lambda: self.open_connection_builder("source"))
        tools.add_separator()
        tools.add_command(label="Rebuild plan", accelerator="F5", command=self.rebuild_plan)
        tools.add_command(label="Refresh tables", command=self.reload_tables)
        menubar.add_cascade(label="Tools", menu=tools)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Open the guide", accelerator="F1", command=self.show_guide)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)
        self.bind_all("<Control-n>", lambda _e: self.new_project())
        self.bind_all("<Control-o>", lambda _e: self.open_project())
        self.bind_all("<Control-s>", lambda _e: self.save_project())
        self.bind_all("<F5>", lambda _e: self.rebuild_plan())
        self.bind_all("<F1>", lambda _e: self.show_guide())

    def show_about(self) -> None:
        messagebox.showinfo(
            "About",
            f"{APP_NAME} {APP_VERSION}\n\n"
            "Bifurcates MySQL identity columns into a separate database.\n"
            "The source table is never modified.\n\n"
            "Requires PyMySQL and Python 3.9+.",
        )

    # -- layout ------------------------------------------------------------

    def _build_layout(self) -> None:
        header = ttk.Frame(self, padding=(14, 10, 14, 2))
        header.pack(fill="x")
        ttk.Label(header, text=APP_NAME, style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Move identity columns into their own database, linked by UUID. Source tables stay intact.",
            style="Sub.TLabel",
        ).pack(anchor="w")

        # Step banner -----------------------------------------------------
        banner = tk.Frame(self, bg=BANNER_BG)
        banner.pack(fill="x", padx=10, pady=(6, 0))
        top_line = tk.Frame(banner, bg=BANNER_BG)
        top_line.pack(fill="x", padx=12, pady=(8, 0))
        self.lbl_step_title = tk.Label(
            top_line, text="", bg=BANNER_BG, fg=BANNER_FG,
            font=("Segoe UI Semibold", 11), anchor="w",
        )
        self.lbl_step_title.pack(side="left")
        guide_link = tk.Label(
            top_line, text="Open the full guide", bg=BANNER_BG, fg="#1b5fbf",
            font=("Segoe UI", 9, "underline"), cursor="hand2",
        )
        guide_link.pack(side="right")
        guide_link.bind("<Button-1>", lambda _e: self.show_guide())
        self.lbl_step_hint = tk.Label(
            banner, text="", bg=BANNER_BG, fg=BANNER_SUB, font=("Segoe UI", 9),
            anchor="w", justify="left", wraplength=980,
        )
        self.lbl_step_hint.pack(fill="x", padx=12, pady=(2, 8))

        # Bottom bars are packed before the body so they always keep their height.
        status = ttk.Frame(self, padding=(12, 4))
        status.pack(fill="x", side="bottom")
        ttk.Label(status, textvariable=self.var_status, style="Sub.TLabel").pack(side="left")
        self.progress = ttk.Progressbar(status, mode="indeterminate", length=170)
        self.progress.pack(side="right")

        nav = ttk.Frame(self, padding=(10, 4, 10, 4))
        nav.pack(fill="x", side="bottom")
        self.btn_back = ttk.Button(nav, text="< Back", command=self._step_back)
        self.btn_back.pack(side="left")
        self.lbl_nav = ttk.Label(nav, text="", style="Sub.TLabel")
        self.lbl_nav.pack(side="left", padx=12)
        self.btn_next = ttk.Button(nav, text="Next >", style="Accent.TButton",
                                   command=self._step_next)
        self.btn_next.pack(side="right")
        ttk.Button(nav, text="Save project", command=self.save_project).pack(
            side="right", padx=8)

        # Body: sidebar + step content ------------------------------------
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=10, pady=6)

        sidebar = tk.Frame(body, bg=SIDEBAR_BG, width=232)
        sidebar.pack(side="left", fill="y", padx=(0, 8))
        sidebar.pack_propagate(False)
        tk.Label(
            sidebar, text="SETUP STEPS", bg=SIDEBAR_BG, fg=SIDEBAR_MUTED,
            font=("Segoe UI Semibold", 8), anchor="w",
        ).pack(fill="x", padx=10, pady=(8, 4))

        self.step_rows: list[tuple[tk.Frame, tk.Label, tk.Label]] = []
        for index, (title, _hint) in enumerate(WIZARD_STEPS):
            row = tk.Frame(sidebar, bg=SIDEBAR_BG, cursor="hand2")
            row.pack(fill="x", padx=6, pady=1)
            number = tk.Label(
                row, text=str(index + 1), width=2, bg=SIDEBAR_BG, fg=SIDEBAR_FG,
                font=("Segoe UI Semibold", 9), padx=2, pady=2,
            )
            number.pack(side="left", padx=(4, 6), pady=5)
            label = tk.Label(
                row, text=title, bg=SIDEBAR_BG, fg=SIDEBAR_FG, anchor="w",
                font=("Segoe UI", 9), padx=2, pady=2,
            )
            label.pack(side="left", fill="x", expand=True, pady=5)
            for widget in (row, number, label):
                widget.bind("<Button-1>", lambda _e, i=index: self._sidebar_click(i))
            self.step_rows.append((row, number, label))

        tk.Frame(sidebar, bg="#dde5f0", height=1).pack(fill="x", padx=10, pady=8)
        self.btn_guide = ttk.Button(sidebar, text="Guide & help", command=self.show_guide)
        self.btn_guide.pack(fill="x", padx=8, pady=2)
        ttk.Button(sidebar, text="New project", command=self.new_project).pack(
            fill="x", padx=8, pady=2)
        tk.Label(
            sidebar,
            text="Your source tables are\nnever modified.",
            bg=SIDEBAR_BG, fg=SIDEBAR_MUTED, font=("Segoe UI", 8),
            justify="left", anchor="w",
        ).pack(side="bottom", fill="x", padx=12, pady=10)

        self.nb = StepStack(body)
        self.nb.pack(side="left", fill="both", expand=True)

        self.tab_conn = ttk.Frame(self.nb, padding=12)
        self.tab_cols = ttk.Frame(self.nb, padding=8)
        self.tab_review = ttk.Frame(self.nb, padding=8)
        self.tab_run = ttk.Frame(self.nb, padding=8)
        self.tab_browse = ttk.Frame(self.nb, padding=8)
        self.tab_help = ttk.Frame(self.nb, padding=8)
        self.nb.add(self.tab_conn, text="Connect")
        self.nb.add(self.tab_cols, text="Columns")
        self.nb.add(self.tab_review, text="Review")
        self.nb.add(self.tab_run, text="Run")
        self.nb.add(self.tab_browse, text="Browse")
        self.nb.add(self.tab_help, text="Guide")

        self._build_connection_tab()
        self._build_columns_tab()
        self._build_review_tab()
        self._build_run_tab()
        self._build_browse_tab()
        self._build_help_tab()
        self.refresh_mapping_views()
        self.nb.bind("<<StepChanged>>", self._on_tab_changed)
        self._sync_wizard()

    def _on_tab_changed(self, _event=None) -> None:
        if str(self.nb.select()) == str(self.tab_browse):
            self.refresh_dataset_options()
        self._sync_wizard()

    # -- wizard chrome ------------------------------------------------------

    def _step_index(self) -> int:
        current = str(self.nb.select())
        for index, tab in enumerate(self.step_tabs()):
            if str(tab) == current:
                return index
        return -1

    def step_tabs(self) -> list:
        return [self.tab_conn, self.tab_cols, self.tab_review, self.tab_run, self.tab_browse]

    def _sync_wizard(self) -> None:
        if self._wizard_syncing or not hasattr(self, "lbl_step_title"):
            return
        self._wizard_syncing = True
        try:
            index = self._step_index()
            on_guide = index < 0
            if on_guide:
                self.lbl_step_title.configure(text="Guide & help")
                self.lbl_step_hint.configure(
                    text="How the tool works, what the generated SQL does, required privileges "
                         "and troubleshooting. Use the sidebar to return to the setup steps.")
                self.lbl_nav.configure(text="Reference")
                self.btn_back.configure(text="< Back to setup", state="normal",
                                        command=self._back_to_steps)
                self.btn_next.configure(text="Back to setup", state="normal",
                                        command=self._back_to_steps)
                self._paint_sidebar(None)
                return
            title, hint = WIZARD_STEPS[index]
            self.lbl_step_title.configure(
                text=f"Step {index + 1} of {len(self.step_tabs())}  \u00b7  {title}")
            self.lbl_step_hint.configure(text=hint)
            self.lbl_nav.configure(text=f"Step {index + 1} of {len(self.step_tabs())}")
            self.btn_back.configure(
                text="< Back", state=("disabled" if index == 0 else "normal"),
                command=self._step_back)
            if index == len(self.step_tabs()) - 1:
                self.btn_next.configure(text="Finish", state="normal", command=self._step_finish)
            else:
                self.btn_next.configure(text="Next >", state="normal", command=self._step_next)
            self._paint_sidebar(index)
        finally:
            self._wizard_syncing = False

    def _paint_sidebar(self, current: int | None) -> None:
        for index, (row, number, label) in enumerate(self.step_rows):
            if current is None:
                bg, fg, num_bg, num_fg, text = SIDEBAR_BG, SIDEBAR_FG, "#dde5f0", SIDEBAR_FG, str(index + 1)
                if index <= self.max_step:
                    bg, num_bg, num_fg = SIDEBAR_DONE_BG, "#cdebd6", "#0b6b2f"
            elif index == current:
                bg, fg, num_bg, num_fg, text = SIDEBAR_CURRENT_BG, "#0d2f63", "#1b4f9c", "#ffffff", str(index + 1)
            elif index < self.max_step:
                bg, fg, num_bg, num_fg, text = SIDEBAR_DONE_BG, SIDEBAR_FG, "#cdebd6", "#0b6b2f", "\u2713"
            else:
                bg, fg, num_bg, num_fg, text = SIDEBAR_BG, SIDEBAR_MUTED, "#dde5f0", SIDEBAR_MUTED, str(index + 1)
            row.configure(bg=bg)
            label.configure(bg=bg, fg=fg)
            number.configure(bg=num_bg, fg=num_fg, text=text)

    def _sidebar_click(self, index: int) -> None:
        if index > self.max_step:
            self.var_status.set("Finish this step with Next before jumping ahead.")
            return
        self.nb.select(self.step_tabs()[index])
        self.after(20, self._sync_wizard)

    def _step_back(self) -> None:
        self._back_to_steps()

    def _back_to_steps(self) -> None:
        index = self._step_index()
        target = self.max_step if index < 0 else max(0, index - 1)
        self.nb.select(self.step_tabs()[target])
        self.after(20, self._sync_wizard)

    def _step_finish(self) -> None:
        messagebox.showinfo(
            "Setup complete",
            "The identity database is ready to use.\n\n"
            "You can keep browsing, export the current page, or run the migration again "
            "at any time - it is safe to re-run and keeps the existing UUIDs.",
        )

    def show_guide(self) -> None:
        self.nb.select(self.tab_help)
        self.after(20, self._sync_wizard)

    def _step_next(self) -> None:
        index = self._step_index()
        if index < 0:
            return
        if not self._validate_step(index):
            return
        if index + 1 >= len(self.step_tabs()):
            self._step_finish()
            return
        self.max_step = max(self.max_step, index + 1)
        self.nb.select(self.step_tabs()[index + 1])
        self.after(20, self._sync_wizard)

    def _validate_step(self, index: int) -> bool:
        if index == 0:
            if not self.connected:
                dsn = self.var_source_dsn.get().strip()
                if not dsn:
                    messagebox.showwarning(
                        "Connect first",
                        "Enter a MySQL connection string, or use Build connection string to "
                        "create one from server address, user and password.")
                    return False
                if not messagebox.askyesno(
                    "Connect now",
                    "Connect to this MySQL server now?\n\n" + dsn_summary(dsn),
                ):
                    return False
                self._advance_after_connect = True
                self.connect_source()
                return False
            if self.var_remote.get():
                if not self.var_ident_dsn.get().strip():
                    messagebox.showwarning(
                        "Identity server",
                        "Tick 'different server' only after entering the identity server "
                        "connection string, or untick it when both databases share a server.")
                    return False
                if not self.id_db.connected:
                    if not messagebox.askyesno(
                        "Connect identity server",
                        "Connect to the identity MySQL server now?\n\n"
                        + dsn_summary(self.var_ident_dsn.get().strip()),
                    ):
                        return False
                    self._advance_after_identity = True
                    self.connect_identity()
                    return False
            return True
        if index == 1:
            if not self.project.mappings:
                messagebox.showwarning(
                    "No mapping yet",
                    "Tick the identity columns you want to hide, then press "
                    "'Add / update mapping'.")
                return False
            if not self.var_identity_db.get().strip():
                messagebox.showwarning("Identity database",
                                       "Enter the name of the new identity database.")
                return False
            return True
        if index == 2:
            if not (self.plan or self.build_plan_or_complain()):
                return False
            return True
        if index == 3:
            if not self.migration_ran:
                if not messagebox.askyesno(
                    "Migration not run yet",
                    "You have not run the migration in this session.\n\n"
                    "Browsing needs the identity tables and views to exist. Continue to "
                    "Browse anyway?",
                ):
                    return False
            return True
        return True


    def _on_close(self) -> None:
        if self.busy and not messagebox.askyesno("Quit", "An operation is running. Quit anyway?"):
            return
        self.src_db.close()
        self.id_db.close()
        self.destroy()

    # -- tab 1: connection -------------------------------------------------

    def _build_connection_tab(self) -> None:
        frm = self.tab_conn
        frm.columnconfigure(0, weight=1)

        proj = ttk.LabelFrame(frm, text="Project", padding=10)
        proj.grid(row=0, column=0, sticky="ew")
        proj.columnconfigure(1, weight=1)
        ttk.Label(proj, text="Project name").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(proj, textvariable=self.var_project, width=60).grid(row=0, column=1, sticky="ew")

        src = ttk.LabelFrame(frm, text="Source MySQL connection", padding=10)
        src.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        src.columnconfigure(0, weight=1)
        ttk.Label(src, text="Full connection string").grid(row=0, column=0, sticky="w")
        ttk.Entry(src, textvariable=self.var_source_dsn).grid(row=1, column=0, sticky="ew", pady=(2, 6))
        row = ttk.Frame(src)
        row.grid(row=2, column=0, sticky="ew")
        self.btn_connect = ttk.Button(row, text="Test & connect", style="Accent.TButton",
                                     command=self.connect_source)
        self.btn_connect.pack(side="left")
        ttk.Button(row, text="Build connection string...",
                   command=lambda: self.open_connection_builder("source")).pack(side="left", padx=6)
        ttk.Label(row, textvariable=self.var_conn_state, style="Sub.TLabel").pack(side="left", padx=10)
        ttk.Label(src, textvariable=self.var_source_summary, style="Mono.TLabel",
                  wraplength=1000).grid(row=3, column=0, sticky="w", pady=(6, 0))
        ttk.Label(
            src,
            text="Accepted: mysql://user:password@host:3306/database?charset=utf8mb4  |  "
                 "host=...;port=...;user=...;password=...;database=...",
            style="Sub.TLabel", wraplength=1000,
        ).grid(row=4, column=0, sticky="w", pady=(2, 0))

        loc = ttk.LabelFrame(frm, text="Where the identity data lives", padding=10)
        loc.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        loc.columnconfigure(0, weight=1)
        ttk.Checkbutton(
            loc, text="The identity database is on a different MySQL server",
            variable=self.var_remote, command=self._toggle_remote,
        ).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(loc, text="Identity server connection string").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.ent_ident_dsn = ttk.Entry(loc, textvariable=self.var_ident_dsn)
        self.ent_ident_dsn.grid(row=2, column=0, sticky="ew", pady=(2, 6))
        self.btn_ident_test = ttk.Button(loc, text="Test identity connection", command=self.connect_identity)
        self.btn_ident_test.grid(row=2, column=1, sticky="w", padx=(6, 0))
        self.btn_ident_build = ttk.Button(
            loc, text="Build...",
            command=lambda: self.open_connection_builder("identity"))
        self.btn_ident_build.grid(row=2, column=2, sticky="w", padx=(6, 0))
        ttk.Label(loc, textvariable=self.var_ident_summary, style="Mono.TLabel",
                  wraplength=1000).grid(row=3, column=0, columnspan=3, sticky="w")
        ttk.Label(
            loc,
            text="Leave unticked when both databases are on the same server: the source connection is used for both.",
            style="Sub.TLabel", wraplength=1000,
        ).grid(row=4, column=0, columnspan=3, sticky="w", pady=(4, 0))
        self._toggle_remote()

        note = ttk.LabelFrame(frm, text="What this tool guarantees", padding=10)
        note.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        ttk.Label(
            note,
            justify="left",
            text=(
                "1. Source tables are read-only: no ALTER, UPDATE or DROP is ever issued against them.\n"
                "2. A new database holds one row per source row: UUID + original identity values + metadata.\n"
                "3. Scripts are idempotent (safe to re-run) and the data load runs in a transaction.\n"
                "4. Re-running only refreshes values whose hash changed; UUIDs are preserved."
            ),
        ).pack(anchor="w")

        frm.rowconfigure(4, weight=1)

    def open_connection_builder(self, which: str = "source") -> None:
        """Toolbox dialog that assembles a connection string from individual fields."""
        var_dsn = self.var_source_dsn if which == "source" else self.var_ident_dsn
        current = var_dsn.get().strip()
        try:
            parsed = parse_dsn(current) if current else None
        except DsnError:
            parsed = None
        base = parsed or {
            "host": "127.0.0.1",
            "port": 3306,
            "user": "root" if which == "source" else "",
            "password": "",
            "database": "",
            "charset": DEFAULT_CHARSET,
        }

        dlg = tk.Toplevel(self)
        dlg.title("Connection string builder")
        dlg.transient(self)
        dlg.resizable(False, False)
        outer = ttk.Frame(dlg, padding=14)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)

        ttk.Label(
            outer,
            text=("Source MySQL server" if which == "source" else "Identity MySQL server"),
            style="Section.TLabel",
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            outer,
            text="Fill in the fields; the connection string is built as you type.",
            style="Sub.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(0, 8))

        form = ttk.Frame(outer)
        form.grid(row=2, column=0, sticky="ew")
        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)

        var_host = tk.StringVar(value=str(base.get("host") or ""))
        var_port = tk.StringVar(value=str(base.get("port") or 3306))
        var_user = tk.StringVar(value=str(base.get("user") or ""))
        var_password = tk.StringVar(value=str(base.get("password") or ""))
        var_database = tk.StringVar(value=str(base.get("database") or ""))
        var_charset = tk.StringVar(value=str(base.get("charset") or DEFAULT_CHARSET))
        var_style = tk.StringVar(value="url")

        ttk.Label(form, text="Server address").grid(row=0, column=0, sticky="w")
        ent_host = ttk.Entry(form, textvariable=var_host, width=28)
        ent_host.grid(row=0, column=1, sticky="ew", padx=(6, 14))
        ttk.Label(form, text="Port").grid(row=0, column=2, sticky="w")
        ttk.Entry(form, textvariable=var_port, width=8).grid(row=0, column=3, sticky="w", padx=(6, 0))

        ttk.Label(form, text="Username").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(form, textvariable=var_user, width=28).grid(
            row=1, column=1, sticky="ew", padx=(6, 14), pady=(8, 0))
        ttk.Label(form, text="Password").grid(row=1, column=2, sticky="w", pady=(8, 0))
        ent_password = ttk.Entry(form, textvariable=var_password, width=18, show="\u2022")
        ent_password.grid(row=1, column=3, sticky="ew", padx=(6, 0), pady=(8, 0))

        ttk.Label(form, text="Database").grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(form, textvariable=var_database, width=28).grid(
            row=2, column=1, sticky="ew", padx=(6, 14), pady=(8, 0))
        ttk.Label(form, text="Charset").grid(row=2, column=2, sticky="w", pady=(8, 0))
        ttk.Entry(form, textvariable=var_charset, width=12).grid(
            row=2, column=3, sticky="w", padx=(6, 0), pady=(8, 0))
        ttk.Label(
            form,
            text="Database = the schema that holds your tables. The table itself is chosen in step 2.",
            style="Sub.TLabel",
        ).grid(row=3, column=0, columnspan=4, sticky="w", pady=(4, 0))

        show_pw = tk.BooleanVar(value=False)

        def toggle_password() -> None:
            ent_password.configure(show="" if show_pw.get() else "\u2022")

        ttk.Checkbutton(form, text="Show password", variable=show_pw,
                        command=toggle_password).grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(6, 0))

        fmt = ttk.Frame(outer)
        fmt.grid(row=3, column=0, sticky="w", pady=(10, 0))
        ttk.Label(fmt, text="Format").pack(side="left")
        ttk.Radiobutton(fmt, text="mysql:// URL", value="url",
                        variable=var_style).pack(side="left", padx=(8, 4))
        ttk.Radiobutton(fmt, text="key=value", value="keyvalue",
                        variable=var_style).pack(side="left", padx=4)

        ttk.Label(outer, text="Connection string", style="Section.TLabel").grid(
            row=4, column=0, sticky="w", pady=(10, 2))
        preview = tk.StringVar()
        preview_entry = ttk.Entry(outer, textvariable=preview, state="readonly",
                                  font=("Consolas", 9))
        preview_entry.grid(row=5, column=0, sticky="ew")
        note = tk.StringVar()
        ttk.Label(outer, textvariable=note, style="Sub.TLabel", wraplength=620,
                  justify="left").grid(row=6, column=0, sticky="w", pady=(4, 0))

        def refresh(*_args) -> None:
            try:
                value = build_dsn(
                    var_host.get(), var_port.get(), var_user.get(), var_password.get(),
                    var_database.get(), var_charset.get(), var_style.get(),
                )
            except DsnError as exc:
                preview.set("")
                note.set(str(exc))
                return
            preview.set(value)
            if var_style.get() == "keyvalue" and ";" in var_password.get():
                note.set("Warning: this format cannot escape ';' inside the password. "
                         "Use the mysql:// URL format for such passwords.")
            else:
                note.set("Use the mysql:// format when the password contains special "
                         "characters; it is URL-encoded automatically.")

        for var in (var_host, var_port, var_user, var_password, var_database,
                    var_charset, var_style):
            var.trace_add("write", lambda *_a: refresh())

        actions = ttk.Frame(outer)
        actions.grid(row=7, column=0, sticky="ew", pady=(12, 0))

        def copy_value() -> None:
            value = preview.get().strip()
            if not value:
                return
            self.clipboard_clear()
            self.clipboard_append(value)
            note.set("Copied to the clipboard.")

        def use_value() -> None:
            try:
                value = build_dsn(
                    var_host.get(), var_port.get(), var_user.get(), var_password.get(),
                    var_database.get(), var_charset.get(), var_style.get(),
                )
            except DsnError as exc:
                messagebox.showerror("Connection string builder", str(exc), parent=dlg)
                return
            var_dsn.set(value)
            if which == "source":
                self.var_source_summary.set(dsn_summary(value))
                self.var_conn_state.set("Connection string changed - press Test & connect")
            else:
                self.var_ident_summary.set(dsn_summary(value))
            self.log(f"{'Source' if which == 'source' else 'Identity'} connection string "
                     "built", "muted")
            dlg.destroy()

        ttk.Button(actions, text="Cancel", command=dlg.destroy).pack(side="right")
        ttk.Button(actions, text="Use this string", style="Accent.TButton",
                   command=use_value).pack(side="right", padx=6)
        ttk.Button(actions, text="Copy", command=copy_value).pack(side="right")

        refresh()
        ent_host.focus_set()
        dlg.bind("<Escape>", lambda _e: dlg.destroy())
        dlg.grab_set()
        self.wait_window(dlg)

    def _toggle_remote(self) -> None:
        remote = bool(self.var_remote.get())
        state = "normal" if remote else "disabled"
        self.ent_ident_dsn.configure(state=state)
        self.btn_ident_test.configure(state=state)
        self.btn_ident_build.configure(state=state)
        if hasattr(self, "cb_browse_dataset"):
            self.refresh_dataset_options()

    def connect_source(self) -> None:
        dsn = self.var_source_dsn.get().strip()
        if not dsn:
            messagebox.showwarning("Connection string", "Enter a MySQL connection string first.")
            return
        try:
            self.src_db.configure(dsn)
        except DsnError as exc:
            messagebox.showerror("Connection string", str(exc))
            return
        self.var_source_summary.set(dsn_summary(dsn))

        def work():
            return self.src_db.connect(), self.src_db.list_databases()

        def done(result):
            _conn, dbs = result
            self.connected = True
            self.var_conn_state.set(f"Connected - MySQL {self.src_db.server_version}")
            self.cb_db["values"] = dbs
            current = self.cb_db.get()
            preferred = self.src_db.params.get("database") or (dbs[0] if dbs else "")
            self.var_db.set(preferred if preferred in dbs else (current if current in dbs else (dbs[0] if dbs else "")))
            if not self.var_identity_db.get():
                base = (self.src_db.params.get("database") or "identity").strip()
                self.var_identity_db.set(clip_ident(base + "_identity"))
            self.project.source_dsn = dsn
            self.log(f"Connected to {dsn_summary(dsn)} (MySQL {self.src_db.server_version})", "ok")
            self.reload_tables()
            if self._advance_after_connect:
                self._advance_after_connect = False
                self.after(120, self._step_next)

        self.run_async("Connecting to MySQL...", work, done)

    def connect_identity(self) -> None:
        dsn = self.var_ident_dsn.get().strip()
        if not dsn:
            messagebox.showwarning("Identity connection", "Enter the identity server connection string.")
            return
        try:
            self.id_db.configure(dsn)
        except DsnError as exc:
            messagebox.showerror("Connection string", str(exc))
            return
        self.id_db.ignore_database = True
        self.var_ident_summary.set(dsn_summary(dsn))

        def done(result):
            _c = result
            self.log(f"Identity server OK: MySQL {self.id_db.server_version}", "ok")
            self.var_ident_summary.set(
                f"{dsn_summary(dsn)}  ->  MySQL {self.id_db.server_version}"
            )
            if self._advance_after_identity:
                self._advance_after_identity = False
                self.after(120, self._step_next)

        self.run_async("Connecting to identity server...", self.id_db.connect, done)

    # -- tab 2: columns ----------------------------------------------------

    def _build_columns_tab(self) -> None:
        frm = self.tab_cols
        paned = ttk.Panedwindow(frm, orient="horizontal")
        paned.pack(fill="both", expand=True)

        left = ttk.Frame(paned, padding=(0, 0, 8, 0))
        right = ttk.Frame(paned, padding=(8, 0, 0, 0))
        paned.add(left, weight=1)
        paned.add(right, weight=3)

        # left: databases + tables
        left.columnconfigure(0, weight=1)
        left.rowconfigure(4, weight=1)
        ttk.Label(left, text="Database", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.cb_db = ttk.Combobox(left, textvariable=self.var_db, state="readonly")
        self.cb_db.grid(row=1, column=0, sticky="ew", pady=(2, 6))
        self.cb_db.bind("<<ComboboxSelected>>", lambda _e: self.on_db_change())

        ttk.Label(left, text="Filter tables", style="Section.TLabel").grid(row=2, column=0, sticky="w")
        ent = ttk.Entry(left, textvariable=self.var_table_filter)
        ent.grid(row=3, column=0, sticky="ew", pady=(2, 4))
        ent.bind("<KeyRelease>", lambda _e: self.render_tables())

        ttk.Label(left, textvariable=self.var_table_count, style="Sub.TLabel").grid(row=5, column=0, sticky="w")
        ttk.Button(left, text="Refresh", command=self.reload_tables).grid(row=6, column=0, sticky="ew", pady=(4, 4))

        tree_wrap = ttk.Frame(left)
        tree_wrap.grid(row=4, column=0, sticky="nsew", pady=(4, 0))
        tree_wrap.columnconfigure(0, weight=1)
        tree_wrap.rowconfigure(0, weight=1)
        self.tv_tables = ttk.Treeview(tree_wrap, columns=("name", "engine", "rows"), show="headings",
                                      selectmode="browse")
        self.tv_tables.heading("name", text="Table")
        self.tv_tables.heading("engine", text="Engine")
        self.tv_tables.heading("rows", text="~Rows")
        self.tv_tables.column("name", width=170)
        self.tv_tables.column("engine", width=55, anchor="center")
        self.tv_tables.column("rows", width=55, anchor="e")
        self.tv_tables.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tv_tables.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.tv_tables.configure(yscrollcommand=sb.set)
        self.tv_tables.bind("<<TreeviewSelect>>", lambda _e: self.on_table_select())

        # right: table details
        right.columnconfigure(0, weight=1)
        right.rowconfigure(5, weight=1)
        self.lbl_table = ttk.Label(right, text="Select a table", style="Section.TLabel")
        self.lbl_table.grid(row=0, column=0, sticky="w")
        self.lbl_pk = ttk.Label(right, text="", style="Sub.TLabel", wraplength=900, justify="left")
        self.lbl_pk.grid(row=1, column=0, sticky="w", pady=(0, 4))

        toolbar = ttk.Frame(right)
        toolbar.grid(row=2, column=0, sticky="ew", pady=(2, 4))
        ttk.Label(toolbar, text="Filter columns").pack(side="left")
        col_filter = ttk.Entry(toolbar, textvariable=self.var_col_filter, width=18)
        col_filter.pack(side="left", padx=(4, 10))
        col_filter.bind("<KeyRelease>", lambda _e: self.render_columns())
        ttk.Button(toolbar, text="All", width=5, command=lambda: self.set_all_columns(True)).pack(side="left")
        ttk.Button(toolbar, text="None", width=5, command=lambda: self.set_all_columns(False)).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Load samples", command=self.load_samples).pack(side="left", padx=(4, 0))
        ttk.Label(toolbar, text="  Click the box (or press Space) to tick a column",
                  style="Sub.TLabel").pack(side="left", padx=8)

        tv_wrap = ttk.Frame(right)
        tv_wrap.grid(row=5, column=0, sticky="nsew")
        tv_wrap.columnconfigure(0, weight=1)
        tv_wrap.rowconfigure(0, weight=1)
        self.tv_cols = ttk.Treeview(tv_wrap, columns=("pick", "name", "type", "nullable", "key", "sample"),
                                    show="headings", selectmode="browse")
        for key, label, width, anchor in (
            ("pick", "Hide", 46, "center"),
            ("name", "Column", 210, "w"),
            ("type", "Type", 160, "w"),
            ("nullable", "Null", 50, "center"),
            ("key", "Key", 60, "center"),
            ("sample", "Sample values", 320, "w"),
        ):
            self.tv_cols.heading(key, text=label)
            self.tv_cols.column(key, width=width, anchor=anchor, stretch=(key == "sample"))
        self.tv_cols.grid(row=0, column=0, sticky="nsew")
        sb2 = ttk.Scrollbar(tv_wrap, orient="vertical", command=self.tv_cols.yview)
        sb2.grid(row=0, column=1, sticky="ns")
        self.tv_cols.configure(yscrollcommand=sb2.set)
        self.tv_cols.bind("<Button-1>", self._on_col_click)
        self.tv_cols.bind("<space>", self._on_col_space)

        form = ttk.LabelFrame(right, text="Mapping for the selected table", padding=8)
        form.grid(row=6, column=0, sticky="ew", pady=(8, 0))
        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)
        ttk.Label(form, text="Identity table").grid(row=0, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.var_ident_table, width=26).grid(row=0, column=1, sticky="ew", padx=(4, 12))
        ttk.Label(form, text="Bifurcated view").grid(row=0, column=2, sticky="w")
        ttk.Entry(form, textvariable=self.var_view, width=30).grid(row=0, column=3, sticky="ew", padx=(4, 0))
        ttk.Label(form, text="Pseudonymized view").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(form, textvariable=self.var_pseudo_view, width=26).grid(row=1, column=1, sticky="ew",
                                                                          padx=(4, 12), pady=(6, 0))
        ttk.Label(form, text="Identity database").grid(row=1, column=2, sticky="w", pady=(6, 0))
        ttk.Entry(form, textvariable=self.var_identity_db, width=30).grid(row=1, column=3, sticky="ew",
                                                                          padx=(4, 0), pady=(6, 0))
        btns = ttk.Frame(form)
        btns.grid(row=2, column=0, columnspan=4, sticky="w", pady=(8, 0))
        ttk.Button(btns, text="Add / update mapping", style="Accent.TButton",
                   command=self.add_mapping).pack(side="left")
        ttk.Button(btns, text="Clear form", command=self.clear_form).pack(side="left", padx=6)
        ttk.Label(btns, text="Double-click a mapping below to edit it", style="Sub.TLabel").pack(side="left", padx=8)

        maps = ttk.LabelFrame(right, text="Mappings in this project", padding=8)
        maps.grid(row=7, column=0, sticky="ew", pady=(8, 0))
        maps.columnconfigure(0, weight=1)
        self.tv_maps = ttk.Treeview(maps, columns=("source", "ident", "cols", "views"),
                                    show="headings", height=4, selectmode="browse")
        for key, label, width in (
            ("source", "Source table", 175),
            ("ident", "Identity table", 150),
            ("cols", "Hidden columns", 300),
            ("views", "Views", 220),
        ):
            self.tv_maps.heading(key, text=label)
            self.tv_maps.column(key, width=width, anchor="w", stretch=True)
        self.tv_maps.grid(row=0, column=0, sticky="ew")
        self.tv_maps.bind("<Double-1>", lambda _e: self.edit_selected_mapping())
        ttk.Button(maps, text="Remove selected mapping",
                   command=self.remove_mapping).grid(row=1, column=0, sticky="w", pady=(6, 0))

    def _on_col_click(self, event):
        region = self.tv_cols.identify("region", event.x, event.y)
        column = self.tv_cols.identify_column(event.x)
        row = self.tv_cols.identify_row(event.y)
        if region == "cell" and column == "#1" and row:
            self.toggle_column(row)
            return "break"
        return None

    def _on_col_space(self, _event):
        row = self.tv_cols.focus()
        if row:
            self.toggle_column(row)
        return "break"

    def toggle_column(self, name: str) -> None:
        values = list(self.tv_cols.item(name, "values"))
        if not values:
            return
        if name in self.ticked:
            self.ticked.discard(name)
            values[0] = "\u2610"
        else:
            self.ticked.add(name)
            values[0] = "\u2611"
        self.tv_cols.item(name, values=values)

    def set_all_columns(self, state: bool) -> None:
        pk = set(self.pk_cache.get((self.current_schema, self.current_table)) or [])
        if not state:
            for name in list(self.ticked):
                self.toggle_column(name)
            return
        for iid in self.tv_cols.get_children():
            if iid not in self.ticked and iid not in pk:
                self.toggle_column(iid)

    def render_tables(self) -> None:
        term = self.var_table_filter.get().strip().lower()
        self.tv_tables.delete(*self.tv_tables.get_children())
        rows = self.tables_cache.get(self.var_db.get()) or []
        shown = 0
        for row in rows:
            name = row.get("name") or ""
            if term and term not in name.lower():
                continue
            est = row.get("rows_est")
            self.tv_tables.insert("", "end", iid=name, values=(
                name, row.get("engine") or "", "" if est is None else f"{int(est):,}"))
            shown += 1
        self.var_table_count.set(f"{shown} of {len(rows)} table(s)")

    def render_columns(self) -> None:
        term = self.var_col_filter.get().strip().lower()
        self.tv_cols.delete(*self.tv_cols.get_children())
        samples = self.samples_cache.get((self.current_schema, self.current_table)) or {}
        for col in self.current_columns:
            name = col.get("name", "")
            if term and term not in name.lower():
                continue
            mark = "\u2611" if name in self.ticked else "\u2610"
            sample = " | ".join(samples.get(name, []))
            self.tv_cols.insert("", "end", iid=name, values=(
                mark, name, col.get("column_type") or "", col.get("is_nullable") or "",
                col.get("key") or "", sample,
            ))

    def apply_table_details(self, schema: str, table: str, cols: list[dict], pk: list[str]) -> None:
        self.current_schema = schema
        self.current_table = table
        self.current_columns = cols
        self.lbl_table.configure(text=f"{schema}.{table}")
        self.lbl_pk.configure(text=("Primary key: " + ", ".join(pk)) if pk else
                              "No primary key: add one to the table (or a unique key) before hiding columns.")
        existing = self.project.mapping_for(schema, table)
        suggestion = existing.identity_columns if existing else [
            c["name"] for c in cols if is_pii_name(c["name"]) and c["name"] not in pk
        ]
        self.ticked = set(suggestion)
        self.var_ident_table.set(existing.identity_table if existing else default_identity_table(table))
        self.var_view.set(existing.view_name if existing else default_view_name(table))
        self.var_pseudo_view.set(existing.pseudo_view_name if existing else default_pseudo_view_name(table))
        self.render_columns()

    def on_db_change(self) -> None:
        db = self.var_db.get()
        if db:
            self.project.options.identity_db = self.var_identity_db.get().strip()
            self.reload_tables()

    def reload_tables(self) -> None:
        db = self.var_db.get()
        if not self.connected or not db:
            return

        def work():
            return db, self.src_db.list_tables(db)

        def done(result):
            schema, rows = result
            self.tables_cache[schema] = rows
            self.render_tables()

        self.run_async(f"Loading tables from {db}...", work, done)

    def on_table_select(self) -> None:
        selection = self.tv_tables.selection()
        if not selection:
            return
        table = selection[0]
        schema = self.var_db.get()
        key = (schema, table)
        self._detail_token += 1
        token = self._detail_token

        def work():
            cols = self.columns_cache.get(key)
            pk = self.pk_cache.get(key)
            if cols is None or pk is None:
                cols = self.src_db.table_columns(schema, table)
                pk = self.src_db.primary_key(schema, table)
                self.columns_cache[key] = cols
                self.pk_cache[key] = pk
            return schema, table, cols, pk

        def done(result):
            if token != self._detail_token:
                return
            s, t, cols, pk = result
            if not pk:
                self.apply_table_details(s, t, cols, [])
                messagebox.showwarning(
                    "Primary key required",
                    f"{s}.{t} has no primary key.\n\n"
                    "The identity table links back to the source row through its primary key, "
                    "so this table cannot be bifurcated until a PK exists.",
                )
                return
            pending = self._pending_mapping
            self._pending_mapping = None
            self.apply_table_details(s, t, cols, pk)
            if pending is not None:
                self.ticked = set(pending.identity_columns)
                self.render_columns()

        self.run_async(f"Inspecting {schema}.{table}...", work, done)

    def load_samples(self) -> None:
        if not (self.current_schema and self.current_table):
            messagebox.showinfo("Samples", "Select a table first.")
            return
        schema, table = self.current_schema, self.current_table
        names = [c["name"] for c in self.current_columns]
        if not names:
            return

        def work():
            return self.src_db.samples(schema, table, names, 200)

        def done(result):
            self.samples_cache[(schema, table)] = result
            self.render_columns()
            self.log(f"Loaded sample values for {schema}.{table}", "muted")

        self.run_async("Loading samples...", work, done)

    def clear_form(self) -> None:
        self.ticked.clear()
        self.render_columns()
        if self.current_table:
            self.var_ident_table.set(default_identity_table(self.current_table))
            self.var_view.set(default_view_name(self.current_table))
            self.var_pseudo_view.set(default_pseudo_view_name(self.current_table))

    def add_mapping(self) -> None:
        if not self.current_table:
            messagebox.showinfo("Mapping", "Select a table first.")
            return
        if not self.ticked:
            messagebox.showwarning("Mapping", "Tick at least one identity column to hide.")
            return
        pk = self.pk_cache.get((self.current_schema, self.current_table)) or []
        if not pk:
            messagebox.showerror("Primary key required", "The selected table has no primary key.")
            return

        itbl = self.var_ident_table.get().strip()
        view = self.var_view.get().strip()
        pview = self.var_pseudo_view.get().strip()
        for label, value in (("Identity table", itbl), ("Bifurcated view", view)):
            if not IDENT_NAME_RE.match(value or ""):
                messagebox.showerror("Invalid name", f"{label} must be 1-64 chars of A-Z, a-z, 0-9, _ or $.")
                return
        if pview and not IDENT_NAME_RE.match(pview):
            messagebox.showerror("Invalid name", "Pseudonymized view must be 1-64 chars of A-Z, a-z, 0-9, _ or $.")
            return
        ident_db = self.var_identity_db.get().strip()
        if not ident_db or not IDENT_NAME_RE.match(ident_db):
            messagebox.showerror("Identity database", "Enter a valid identity database name (A-Z, a-z, 0-9, _ or $).")
            return
        if ident_db.lower() == self.current_schema.lower():
            messagebox.showerror("Identity database",
                                 "The identity database must be different from the source database.")
            return

        mapping = Mapping(
            source_schema=self.current_schema,
            source_table=self.current_table,
            pk_columns=list(pk),
            identity_columns=[c["name"] for c in self.current_columns if c["name"] in self.ticked],
            identity_table=itbl,
            view_name=view,
            pseudo_view_name=pview,
            columns=[dict(c) for c in self.current_columns],
        )
        existing = self.project.mapping_for(mapping.source_schema, mapping.source_table)
        if existing and not messagebox.askyesno(
            "Replace mapping", f"A mapping for {mapping.key} already exists. Replace it?"
        ):
            return
        if existing:
            self.project.mappings.remove(existing)
        self.project.mappings.append(mapping)
        self.project.options.identity_db = ident_db
        self._invalidate_plan()
        self.refresh_mapping_views()
        self.log(f"Mapping added: {mapping.key} -> {ident_db}.{itbl} "
                 f"({len(mapping.identity_columns)} column(s))", "ok")

    def refresh_mapping_views(self) -> None:
        self.tv_maps.delete(*self.tv_maps.get_children())
        for idx, m in enumerate(self.project.mappings):
            self.tv_maps.insert("", "end", iid=str(idx), values=(
                m.key, m.identity_table, ", ".join(m.identity_columns),
                " + ".join(x for x in (m.view_name, m.pseudo_view_name) if x),
            ))
        if hasattr(self, "cb_browse_mapping"):
            self.cb_browse_mapping["values"] = [m.key for m in self.project.mappings]
            if self.project.mappings and self.var_browse_mapping.get() not in [
                m.key for m in self.project.mappings
            ]:
                self.var_browse_mapping.set(self.project.mappings[0].key)

    def edit_selected_mapping(self) -> None:
        selection = self.tv_maps.selection()
        if not selection:
            return
        idx = int(selection[0])
        if idx >= len(self.project.mappings):
            return
        m = self.project.mappings[idx]
        self.var_db.set(m.source_schema)
        self._pending_mapping = m
        if m.source_schema not in self.tables_cache:
            self.load_tables_for(m.source_schema)
        else:
            self.render_tables()
            if self.tv_tables.exists(m.source_table):
                self.tv_tables.selection_set(m.source_table)

    def load_tables_for(self, schema: str) -> None:
        def work():
            return self.src_db.list_tables(schema)

        def done(rows):
            self.tables_cache[schema] = rows
            self.render_tables()
            pending = self._pending_mapping
            if pending and self.tv_tables.exists(pending.source_table):
                self.tv_tables.selection_set(pending.source_table)

        self.run_async(f"Loading tables from {schema}...", work, done)

    def remove_mapping(self) -> None:
        selection = self.tv_maps.selection()
        if not selection:
            return
        idx = int(selection[0])
        if idx >= len(self.project.mappings):
            return
        m = self.project.mappings[idx]
        if not messagebox.askyesno("Remove mapping", f"Remove the mapping for {m.key}?"):
            return
        self.project.mappings.pop(idx)
        self._invalidate_plan()
        self.refresh_mapping_views()
        self.log(f"Mapping removed: {m.key}", "warn")


    # -- tab 3: review -----------------------------------------------------

    def _build_review_tab(self) -> None:
        frm = self.tab_review
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(2, weight=1)

        bar = ttk.Frame(frm)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        ttk.Button(bar, text="Rebuild plan (F5)", style="Accent.TButton",
                   command=self.rebuild_plan).pack(side="left")
        ttk.Button(bar, text="Export SQL...", command=self.export_script).pack(side="left", padx=6)
        ttk.Button(bar, text="Copy SQL", command=self.copy_sql).pack(side="left")
        self.lbl_plan_state = ttk.Label(bar, text="No plan yet", style="Sub.TLabel")
        self.lbl_plan_state.pack(side="left", padx=12)

        top = ttk.Frame(frm)
        top.grid(row=1, column=0, sticky="ew")
        top.columnconfigure(0, weight=3)
        top.columnconfigure(1, weight=2)

        obj_wrap = ttk.LabelFrame(top, text="Objects the script creates", padding=6)
        obj_wrap.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        obj_wrap.columnconfigure(0, weight=1)
        self.tv_objects = ttk.Treeview(obj_wrap, columns=("kind", "name", "db", "note"),
                                       show="headings", height=6)
        for key, label, width in (
            ("kind", "Kind", 80), ("name", "Name", 190), ("db", "Database", 150), ("note", "Note", 240),
        ):
            self.tv_objects.heading(key, text=label)
            self.tv_objects.column(key, width=width, anchor="w", stretch=True)
        self.tv_objects.grid(row=0, column=0, sticky="nsew")

        warn_wrap = ttk.LabelFrame(top, text="Warnings", padding=6)
        warn_wrap.grid(row=0, column=1, sticky="nsew")
        warn_wrap.columnconfigure(0, weight=1)
        warn_wrap.rowconfigure(0, weight=1)
        self.txt_warn = tk.Text(warn_wrap, height=6, wrap="word", font=("Segoe UI", 9),
                                background="#fffdf2", relief="flat")
        self.txt_warn.grid(row=0, column=0, sticky="nsew")
        ws = ttk.Scrollbar(warn_wrap, orient="vertical", command=self.txt_warn.yview)
        ws.grid(row=0, column=1, sticky="ns")
        self.txt_warn.configure(yscrollcommand=ws.set, state="disabled")

        sql_wrap = ttk.LabelFrame(frm, text="Generated SQL (read-only preview)", padding=6)
        sql_wrap.grid(row=2, column=0, sticky="nsew", pady=(8, 0))
        sql_wrap.columnconfigure(0, weight=1)
        sql_wrap.rowconfigure(0, weight=1)
        self.txt_sql = tk.Text(sql_wrap, wrap="none", font=("Consolas", 9), undo=False)
        self.txt_sql.grid(row=0, column=0, sticky="nsew")
        ys = ttk.Scrollbar(sql_wrap, orient="vertical", command=self.txt_sql.yview)
        ys.grid(row=0, column=1, sticky="ns")
        xs = ttk.Scrollbar(sql_wrap, orient="horizontal", command=self.txt_sql.xview)
        xs.grid(row=1, column=0, sticky="ew")
        self.txt_sql.configure(yscrollcommand=ys.set, xscrollcommand=xs.set, state="disabled")

    def _invalidate_plan(self) -> None:
        self.plan = None
        if hasattr(self, "lbl_plan_state"):
            self.lbl_plan_state.configure(text="Plan stale - press Rebuild (F5)")

    def rebuild_plan(self) -> None:
        plan = self.build_plan_or_complain()
        if plan:
            self.log(f"Plan rebuilt: {len(plan.mapping_sqls)} mapping(s) -> "
                     f"{plan.project.options.identity_db}", "ok")

    def build_plan_or_complain(self) -> Plan | None:
        project = self.collect_project()
        errors = validate_project(project)
        if errors:
            messagebox.showerror("Fix these first", "\n".join("\u2022 " + e for e in errors))
            return None
        plan = build_plan(project)
        self.plan = plan
        self.render_plan(plan)
        return plan

    def render_plan(self, plan: Plan) -> None:
        self.tv_objects.delete(*self.tv_objects.get_children())
        for kind, name, db, note in plan.objects():
            self.tv_objects.insert("", "end", values=(kind, name, db, note))

        self.txt_warn.configure(state="normal")
        self.txt_warn.delete("1.0", "end")
        for warning in plan.warnings:
            self.txt_warn.insert("end", "\u2022 " + warning + "\n\n")
        self.txt_warn.configure(state="disabled")

        self.txt_sql.configure(state="normal")
        self.txt_sql.delete("1.0", "end")
        self.txt_sql.insert("1.0", plan.script_text)
        self.txt_sql.configure(state="disabled")

        mode = "separate servers" if plan.cross_server else "same server"
        self.lbl_plan_state.configure(
            text=f"{len(plan.mapping_sqls)} mapping(s) -> {plan.project.options.identity_db}  ({mode})")

    def copy_sql(self) -> None:
        plan = self.plan or self.build_plan_or_complain()
        if not plan:
            return
        self.clipboard_clear()
        self.clipboard_append(plan.script_text)
        self.log("SQL copied to clipboard", "muted")

    def export_script(self) -> None:
        plan = self.plan or self.build_plan_or_complain()
        if not plan:
            return
        default = re.sub(r"[^A-Za-z0-9_-]+", "_", plan.project.name).strip("_") or "identity_bifurcation"
        path = filedialog.asksaveasfilename(
            title="Export SQL script",
            defaultextension=".sql",
            initialfile=default + ".sql",
            filetypes=[("SQL script", "*.sql"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(plan.script_text)
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        self.log(f"SQL exported to {path}", "ok")

    # -- tab 4: run --------------------------------------------------------

    def _build_run_tab(self) -> None:
        frm = self.tab_run
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(2, weight=1)

        opts = ttk.LabelFrame(frm, text="Run options", padding=8)
        opts.grid(row=0, column=0, sticky="ew")
        opts.columnconfigure(0, weight=1)
        opts.columnconfigure(1, weight=1)

        ttk.Checkbutton(
            opts, text="Skip source rows where every identity column is empty",
            variable=self.var_skip_empty, command=self._invalidate_plan,
        ).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(
            opts, text="Delete identity rows whose source row no longer exists",
            variable=self.var_delete_stale, command=self._invalidate_plan,
        ).grid(row=0, column=1, sticky="w")
        ttk.Checkbutton(
            opts, text="Create pseudonymized view (source columns without PII)",
            variable=self.var_pseudo_on, command=self._invalidate_plan,
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))
        ttk.Checkbutton(
            opts, text="Wrap data load in a stored procedure with ROLLBACK handler",
            variable=self.var_use_proc, command=self._invalidate_plan,
        ).grid(row=1, column=1, sticky="w", pady=(4, 0))
        ttk.Checkbutton(
            opts, text="Store passwords inside the saved project file (not recommended)",
            variable=self.var_include_secrets,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        bar = ttk.Frame(frm)
        bar.grid(row=1, column=0, sticky="ew", pady=(8, 4))
        ttk.Button(bar, text="Save project", command=self.save_project).pack(side="left")
        ttk.Button(bar, text="Save project as...", command=self.save_project_as).pack(side="left", padx=6)
        ttk.Button(bar, text="Export SQL...", command=self.export_script).pack(side="left")
        ttk.Button(bar, text="Clear log", command=self.clear_log).pack(side="left", padx=6)
        self.btn_run = ttk.Button(bar, text="Run migration", style="Accent.TButton",
                                  command=self.run_migration)
        self.btn_run.pack(side="right")

        log_wrap = ttk.LabelFrame(frm, text="Log", padding=6)
        log_wrap.grid(row=2, column=0, sticky="nsew")
        log_wrap.columnconfigure(0, weight=1)
        log_wrap.rowconfigure(0, weight=1)
        self.txt_log = tk.Text(log_wrap, wrap="word", font=("Consolas", 9), state="disabled")
        self.txt_log.grid(row=0, column=0, sticky="nsew")
        ys = ttk.Scrollbar(log_wrap, orient="vertical", command=self.txt_log.yview)
        ys.grid(row=0, column=1, sticky="ns")
        self.txt_log.configure(yscrollcommand=ys.set)
        for tag, (fg, bg) in TAG_COLORS.items():
            self.txt_log.tag_configure(tag, foreground=fg, background=bg or self.txt_log["background"])

    def _sanitize(self, text: str) -> str:
        secrets = []
        for db in (self.src_db, self.id_db):
            if db.params and db.params.get("password"):
                secrets.append(db.params["password"])
        for secret in secrets:
            if secret and len(secret) >= 2:
                text = text.replace(secret, "***")
        return text

    def log(self, message: str, tag: str = "info") -> None:
        if not hasattr(self, "txt_log"):
            return
        text = self._sanitize(str(message))
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", text.rstrip() + "\n", tag)
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def clear_log(self) -> None:
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")

    def run_migration(self) -> None:
        plan = self.build_plan_or_complain()
        if not plan:
            return
        if not self.connected:
            messagebox.showerror("Not connected", "Connect to the source MySQL server first (step 1, Connect).")
            return
        current_dsn = self.var_source_dsn.get().strip()
        if self.src_db.dsn and current_dsn != self.src_db.dsn:
            messagebox.showerror(
                "Reconnect required",
                "The connection string changed after connecting.\n\n"
                "Press 'Test & connect' in step 1 so the plan runs against the server you see.",
            )
            return
        project = plan.project
        if plan.cross_server:
            dsn = self.var_ident_dsn.get().strip()
            if not dsn:
                messagebox.showerror("Identity server", "Enter the identity server connection string.")
                return
            try:
                self.id_db.configure(dsn)
            except DsnError as exc:
                messagebox.showerror("Identity connection string", str(exc))
                return
            self.id_db.ignore_database = True

        target = "the identity server" if plan.cross_server else "the same server"
        tables = "\n".join(f"  - {ms.mapping.key} -> {project.options.identity_db}.{ms.mapping.identity_table}"
                           for ms in plan.mapping_sqls)
        if not messagebox.askyesno(
            "Run migration",
            f"Create/refresh the identity database on {target}?\n\n"
            f"Identity database: {project.options.identity_db}\n{tables}\n\n"
            "Source tables are NOT modified.\n"
            "The data load is wrapped in a transaction and rolled back on error.\n\n"
            "Continue?",
        ):
            return

        dst = self.id_db if plan.cross_server else self.src_db

        def emit(kind, message):
            if kind == "progress":
                self.post(lambda: self.var_status.set("Loading rows... " + message))
                return
            self.post(lambda: self.log(message, kind))

        def progress(done, total):
            self.post(lambda: self.var_status.set(f"Running... {done}/{total} statements"))

        def work():
            self.src_db.connect()
            if plan.cross_server:
                dst.connect()
            self.post(lambda: self.log("=" * 70, "muted"))
            self.post(lambda: self.log(f"Running migration for '{project.name}'", "info"))
            execute_plan(plan, self.src_db, dst, emit, progress)
            return True

        def done(_result):
            self.migration_ran = True
            self.max_step = max(self.max_step, 4)
            self.log("Migration finished successfully.", "ok")
            if messagebox.askyesno("Finished", "Migration finished.\n\nOpen the Browse step to inspect the result?"):
                self.nb.select(self.tab_browse)
                self.after(20, self._sync_wizard)
                self.refresh_mapping_views()
                self.load_browse_page(reset=True)

        def failed(exc):
            self.show_error(
                "Migration failed",
                f"{exc}\n\nData changes were rolled back. DDL such as CREATE DATABASE / CREATE TABLE "
                "may already be applied; the script is safe to run again.",
                traceback.format_exc(),
            )

        self.run_async("Running migration...", work, done, failed)

    # -- project I/O -------------------------------------------------------

    def collect_project(self) -> Project:
        self.project.name = self.var_project.get().strip() or "Untitled project"
        self.project.source_dsn = self.var_source_dsn.get().strip()
        self.project.options.same_server = not bool(self.var_remote.get())
        self.project.options.identity_dsn = self.var_ident_dsn.get().strip()
        self.project.options.identity_db = self.var_identity_db.get().strip()
        self.project.options.skip_empty = bool(self.var_skip_empty.get())
        self.project.options.delete_stale = bool(self.var_delete_stale.get())
        self.project.options.make_pseudonymized_view = bool(self.var_pseudo_on.get())
        self.project.options.use_proc = bool(self.var_use_proc.get())
        return self.project

    def _apply_project_to_ui(self, project: Project, path: str | None) -> None:
        self.project = project
        self.project_path = path
        self.var_project.set(project.name)
        self.var_source_dsn.set(project.source_dsn)
        self.var_remote.set(not project.options.same_server)
        self.var_ident_dsn.set(project.options.identity_dsn)
        self.var_identity_db.set(project.options.identity_db)
        self.var_skip_empty.set(project.options.skip_empty)
        self.var_delete_stale.set(project.options.delete_stale)
        self.var_pseudo_on.set(project.options.make_pseudonymized_view)
        self.var_use_proc.set(project.options.use_proc)
        self.var_include_secrets.set(project.options.include_secrets)
        self.var_source_summary.set(dsn_summary(project.source_dsn) if project.source_dsn else "")
        self.var_ident_summary.set(dsn_summary(project.options.identity_dsn)
                                   if project.options.identity_dsn else "")
        self._toggle_remote()
        self.connected = False
        self.var_conn_state.set("Not connected")
        self._invalidate_plan()
        self.refresh_mapping_views()
        self.tv_objects.delete(*self.tv_objects.get_children())
        self.txt_sql.configure(state="normal")
        self.txt_sql.delete("1.0", "end")
        self.txt_sql.configure(state="disabled")
        self.max_step = 0
        self.migration_ran = False
        self.nb.select(self.tab_conn)
        self.after(20, self._sync_wizard)
        self.title(f"{APP_NAME} {APP_VERSION} - {project.name}")

    def new_project(self) -> None:
        if not messagebox.askyesno("New project", "Discard the current project and start a new one?"):
            return
        self._apply_project_to_ui(Project(), None)
        self.clear_log()
        self.log("New project created. Connect to a source server to begin.", "info")

    def save_project(self) -> None:
        if not self.project_path:
            self.save_project_as()
            return
        self._write_project(self.project_path)

    def save_project_as(self) -> None:
        default = re.sub(r"[^A-Za-z0-9_-]+", "_", self.var_project.get()).strip("_") or "project"
        path = filedialog.asksaveasfilename(
            title="Save project",
            defaultextension=PROJECT_SUFFIX,
            initialfile=default + PROJECT_SUFFIX,
            filetypes=[("Identity project", "*" + PROJECT_SUFFIX), ("JSON", "*.json"), ("All files", "*.*")],
        )
        if path:
            self._write_project(path)

    def _write_project(self, path: str) -> None:
        project = self.collect_project()
        try:
            data = project.to_dict(include_secrets=bool(self.var_include_secrets.get()))
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(data, handle, indent=2, ensure_ascii=False)
            os.replace(tmp, path)
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc))
            return
        self.project_path = path
        self.title(f"{APP_NAME} {APP_VERSION} - {project.name}")
        self.log(f"Project saved to {path}", "ok")
        if not self.var_include_secrets.get():
            self.log("Passwords were not written to the project file.", "muted")

    def open_project(self) -> None:
        path = filedialog.askopenfilename(
            title="Open project",
            filetypes=[("Identity project", "*" + PROJECT_SUFFIX + " *.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            project = Project.from_dict(data)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Open failed", str(exc))
            return

        if project.source_dsn:
            try:
                params = parse_dsn(project.source_dsn)
            except DsnError:
                params = {}
            if params and not params.get("password"):
                secret = self.ask_password("Source password",
                                           f"{params.get('user')}@{params.get('host')} / {params.get('database')}")
                if secret is not None:
                    project.source_dsn = self._inject_password(project.source_dsn, secret)
        if project.options.identity_dsn and not project.options.same_server:
            try:
                params = parse_dsn(project.options.identity_dsn)
            except DsnError:
                params = {}
            if params and not params.get("password"):
                secret = self.ask_password("Identity server password",
                                           f"{params.get('user')}@{params.get('host')}")
                if secret is not None:
                    project.options.identity_dsn = self._inject_password(project.options.identity_dsn, secret)

        self._apply_project_to_ui(project, path)
        self.log(f"Project loaded from {path}", "ok")
        if project.mappings:
            self.var_db.set(project.mappings[0].source_schema)
            self.cb_db["values"] = sorted({m.source_schema for m in project.mappings})
        if project.source_dsn:
            self.var_conn_state.set("Not connected - press 'Test & connect'")

    def _inject_password(self, dsn: str, password: str) -> str:
        try:
            p = parse_dsn(dsn)
        except DsnError:
            return dsn
        user = quote(p["user"], safe="")
        pw = quote(password, safe="")
        db = quote(p["database"], safe="")
        return f"mysql://{user}:{pw}@{p['host']}:{p['port']}/{db}?charset={p['charset']}"

    def ask_password(self, title: str, who: str) -> str | None:
        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.transient(self)
        dlg.resizable(False, False)
        ttk.Label(dlg, text=f"Password for {who}", padding=(12, 12, 12, 4)).pack(anchor="w")
        var = tk.StringVar()
        entry = ttk.Entry(dlg, textvariable=var, show="\u2022", width=40)
        entry.pack(padx=12, pady=4)
        result = {"value": None}

        def ok():
            result["value"] = var.get()
            dlg.destroy()

        buttons = ttk.Frame(dlg, padding=12)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="OK", command=ok).pack(side="right")
        ttk.Button(buttons, text="Cancel", command=dlg.destroy).pack(side="right", padx=6)
        entry.focus_set()
        dlg.bind("<Return>", lambda _e: ok())
        dlg.grab_set()
        self.wait_window(dlg)
        return result["value"]

    def prompt_text(self, title: str, label: str, initial: str = "",
                    hint: str = "") -> str | None:
        """Small single-line text prompt. Returns None when cancelled."""
        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.transient(self)
        dlg.resizable(False, False)
        ttk.Label(dlg, text=label, padding=(12, 12, 12, 4)).pack(anchor="w")
        var = tk.StringVar(value=initial)
        entry = ttk.Entry(dlg, textvariable=var, width=52)
        entry.pack(padx=12, pady=4, fill="x")
        if hint:
            ttk.Label(dlg, text=hint, style="Sub.TLabel", wraplength=420,
                      padding=(12, 0, 12, 4)).pack(anchor="w")
        result = {"value": None}

        def ok():
            result["value"] = var.get().strip()
            dlg.destroy()

        buttons = ttk.Frame(dlg, padding=12)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="OK", command=ok).pack(side="right")
        ttk.Button(buttons, text="Cancel", command=dlg.destroy).pack(side="right", padx=6)
        entry.focus_set()
        entry.select_range(0, "end")
        dlg.bind("<Return>", lambda _e: ok())
        dlg.bind("<Escape>", lambda _e: dlg.destroy())
        dlg.grab_set()
        self.wait_window(dlg)
        value = result["value"]
        return value if value else None


    # -- tab 5: browse -----------------------------------------------------

    def _build_browse_tab(self) -> None:
        frm = self.tab_browse
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(2, weight=1)

        bar = ttk.Frame(frm)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        ttk.Label(bar, text="Mapping").pack(side="left")
        self.cb_browse_mapping = ttk.Combobox(bar, textvariable=self.var_browse_mapping,
                                              state="readonly", width=30)
        self.cb_browse_mapping.pack(side="left", padx=(4, 12))
        self.cb_browse_mapping.bind("<<ComboboxSelected>>", lambda _e: self.refresh_dataset_options())

        ttk.Label(bar, text="Show").pack(side="left")
        self.cb_browse_dataset = ttk.Combobox(bar, textvariable=self.var_browse_dataset,
                                              state="readonly", width=28)
        self.cb_browse_dataset.pack(side="left", padx=(4, 12))

        ttk.Label(bar, text="Page size").pack(side="left")
        self.cb_page_size = ttk.Combobox(bar, textvariable=self.var_page_size, state="readonly",
                                         width=6, values=("25", "50", "100", "200", "500"))
        self.cb_page_size.pack(side="left", padx=(4, 12))

        ttk.Label(bar, text="Search").pack(side="left")
        ent = ttk.Entry(bar, textvariable=self.var_browse_filter, width=26)
        ent.pack(side="left", padx=(4, 6))
        ent.bind("<Return>", lambda _e: self.load_browse_page(reset=True))
        ttk.Button(bar, text="Load", command=lambda: self.load_browse_page(reset=True)).pack(side="left")

        export_btn = ttk.Menubutton(bar, text="Export page", style="Accent.TButton")
        export_menu = tk.Menu(export_btn, tearoff=0)
        export_menu.add_command(label="CSV (.csv)", command=self.export_browse_csv)
        export_menu.add_command(label="Excel workbook (.xlsx)", command=self.export_browse_xlsx)
        export_menu.add_separator()
        export_menu.add_command(label="SQL INSERT (.sql)...", command=self.export_browse_sql)
        export_btn["menu"] = export_menu
        export_btn.pack(side="left", padx=6)

        ttk.Label(frm, textvariable=self.var_browse_info, style="Sub.TLabel").grid(
            row=1, column=0, sticky="w", pady=(0, 2))

        wrap = ttk.Frame(frm)
        wrap.grid(row=2, column=0, sticky="nsew")
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)
        self.tv_browse = ttk.Treeview(wrap, show="headings", selectmode="browse")
        self.tv_browse.grid(row=0, column=0, sticky="nsew")
        ys = ttk.Scrollbar(wrap, orient="vertical", command=self.tv_browse.yview)
        ys.grid(row=0, column=1, sticky="ns")
        xs = ttk.Scrollbar(wrap, orient="horizontal", command=self.tv_browse.xview)
        xs.grid(row=1, column=0, sticky="ew")
        self.tv_browse.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)

        nav = ttk.Frame(frm)
        nav.grid(row=3, column=0, sticky="ew", pady=(6, 0))
        ttk.Button(nav, text="< Previous", command=lambda: self.goto_page(-1)).pack(side="left")
        ttk.Label(nav, textvariable=self.var_page_label, style="Sub.TLabel").pack(side="left", padx=10)
        ttk.Button(nav, text="Next >", command=lambda: self.goto_page(1)).pack(side="left")

    def refresh_dataset_options(self) -> None:
        mapping = self.selected_mapping()
        options = ["Identity table only"]
        if mapping and not self.var_remote.get():
            options = ["Bifurcated view"]
            if self.var_pseudo_on.get() and mapping.pseudo_view_name:
                options.append("Pseudonymized view")
            options.append("Identity table only")
        else:
            options.append("Source + identity (in-app join)")
        self.cb_browse_dataset["values"] = options
        if self.var_browse_dataset.get() not in options:
            self.var_browse_dataset.set(options[0])

    def selected_mapping(self) -> Mapping | None:
        key = self.var_browse_mapping.get()
        for m in self.project.mappings:
            if m.key == key:
                return m
        return self.project.mappings[0] if self.project.mappings else None

    def goto_page(self, delta: int) -> None:
        size = int(self.var_page_size.get() or 50)
        page = self.browse_page + delta
        if page < 0:
            return
        if page * size >= max(self.browse_total, 1) and delta > 0:
            return
        self.browse_page = page
        self.load_browse_page()

    def load_browse_page(self, reset: bool = False) -> None:
        mapping = self.selected_mapping()
        if mapping is None:
            self.var_browse_info.set("Add a mapping in step 2 (Choose columns) first.")
            return
        if not self.connected:
            self.var_browse_info.set("Not connected. Connect in step 1, then run the migration.")
            return
        dataset = self.var_browse_dataset.get()
        if reset:
            self.browse_page = 0
        size = int(self.var_page_size.get() or 50)
        offset = self.browse_page * size
        term = self.var_browse_filter.get().strip()

        def work():
            return self._browse_fetch(mapping, dataset, offset, size, term)

        def done(result):
            cols, rows, total = result
            self.browse_total = total
            self.render_browse(cols, rows, total, offset)

        self.run_async("Loading rows...", work, done)

    def _browse_fetch(self, mapping: Mapping, dataset: str, offset: int, size: int, term: str):
        idb = self.project.options.identity_db
        id_db = self.id_db if self.var_remote.get() else self.src_db
        links, idents = plan_column_names(mapping)
        where_sql, where_args = "", []

        if dataset == "Identity table only":
            table = fq(idb, mapping.identity_table)
            cols = id_db.describe(f"SELECT * FROM {table} LIMIT 0")
            if term:
                where_sql, where_args = self._filter_sql(cols, term)
            order = ", ".join(sql_ident(t) for _s, t, _c in links)
            total = int(id_db.scalar(f"SELECT COUNT(*) FROM {table}{where_sql}", tuple(where_args)) or 0)
            rows = id_db.q(
                f"SELECT * FROM {table}{where_sql} ORDER BY {order} LIMIT %s OFFSET %s",
                tuple(where_args) + (size, offset),
            )
            return cols, rows, total

        if dataset == "Source + identity (in-app join)":
            table = fq(idb, mapping.identity_table)
            id_cols = id_db.describe(f"SELECT * FROM {table} LIMIT 0")
            if term:
                where_sql, where_args = self._filter_sql(id_cols, term)
            order = ", ".join(sql_ident(t) for _s, t, _c in links)
            total = int(id_db.scalar(f"SELECT COUNT(*) FROM {table}{where_sql}", tuple(where_args)) or 0)
            id_rows = id_db.q(
                f"SELECT * FROM {table}{where_sql} ORDER BY {order} LIMIT %s OFFSET %s",
                tuple(where_args) + (size, offset),
            )
            keys = [tuple(r.get(t) for _s, t, _c in links) for r in id_rows]
            src_map = self._fetch_source_rows(mapping, keys) if keys else {}
            prefix = source_columns_to_view_prefix(mapping)
            out_cols = [c["name"] for c in mapping.columns]
            out_cols.append(prefix + "uuid")
            out_cols.extend(prefix + t for _s, t, _c in idents)
            out_cols.append(prefix + "created_at")
            merged = []
            for id_row in id_rows:
                key = tuple(id_row.get(t) for _s, t, _c in links)
                src_row = src_map.get(key, {})
                row = {name: src_row.get(name) for name in [x["name"] for x in mapping.columns]}
                row[prefix + "uuid"] = id_row.get(META_UUID)
                for _s, t, _c in idents:
                    row[prefix + t] = id_row.get(t)
                row[prefix + "created_at"] = id_row.get(META_CREATED)
                merged.append(row)
            return out_cols, merged, total

        view_name = mapping.view_name if dataset == "Bifurcated view" else mapping.pseudo_view_name
        if not view_name:
            raise RuntimeError(f"{dataset} is not configured for {mapping.key}.")
        table = fq(idb, view_name)
        cols = id_db.describe(f"SELECT * FROM {table} LIMIT 0")
        if term:
            where_sql, where_args = self._filter_sql(cols, term)
        order_cols = [c for c in mapping.pk_columns if c in cols] or cols[:1]
        order = ", ".join(sql_ident(c) for c in order_cols)
        total = int(id_db.scalar(f"SELECT COUNT(*) FROM {table}{where_sql}", tuple(where_args)) or 0)
        rows = id_db.q(
            f"SELECT * FROM {table}{where_sql} ORDER BY {order} LIMIT %s OFFSET %s",
            tuple(where_args) + (size, offset),
        )
        return cols, rows, total

    @staticmethod
    def _filter_sql(cols: list[str], term: str) -> tuple[str, list]:
        expr = "CONCAT_WS(' ', " + ", ".join(
            f"IFNULL(CAST({sql_ident(c)} AS CHAR), '')" for c in cols
        ) + ")"
        return f" WHERE {expr} LIKE %s", ["%" + term + "%"]

    def _fetch_source_rows(self, mapping: Mapping, keys: list[tuple]) -> dict:
        if not keys:
            return {}
        pk = mapping.pk_columns
        conds = []
        args = []
        for key in keys:
            conds.append("(" + " AND ".join(f"{sql_ident(c)} = %s" for c in pk) + ")")
            args.extend(key)
        sql = (f"SELECT * FROM {fq(mapping.source_schema, mapping.source_table)} "
               f"WHERE " + " OR ".join(conds))
        rows = self.src_db.q(sql, tuple(args))
        return {tuple(r.get(c) for c in pk): r for r in rows}

    def render_browse(self, cols: list[str], rows: list[dict], total: int, offset: int) -> None:
        self.browse_cols = cols
        self.browse_rows = rows
        tv = self.tv_browse
        tv.delete(*tv.get_children())
        tv.configure(columns=cols)
        for name in cols:
            width = len(name)
            for row in rows[:40]:
                width = max(width, len(cell_text(row.get(name), 48)))
            tv.heading(name, text=name)
            tv.column(name, width=min(max(width * 7, 70), 340), anchor="w", stretch=False)
        for row in rows:
            tv.insert("", "end", values=tuple(cell_text(row.get(c)) for c in cols))

        size = int(self.var_page_size.get() or 50)
        pages = max(1, (total + size - 1) // size)
        start = offset + 1 if total else 0
        end = min(offset + len(rows), total)
        self.var_browse_info.set(
            f"{total:,} row(s) in total - showing {start:,}-{end:,}"
            + (" (filtered)" if self.var_browse_filter.get().strip() else "")
        )
        self.var_page_label.set(f"Page {self.browse_page + 1} of {pages}")

    def _require_browse_page(self) -> bool:
        if not self.browse_rows:
            messagebox.showinfo("Export", "Load a page in the Browse step first, then export.")
            return False
        return True

    def _export_basename(self, extension: str) -> str:
        mapping = self.selected_mapping()
        base = (mapping.source_table if mapping else "") or "page"
        dataset = self.var_browse_dataset.get()
        if dataset == "Identity table only":
            base += "_identity"
        elif dataset == "Pseudonymized view":
            base += "_pseudonymized"
        elif dataset.startswith("Source"):
            base += "_merged"
        else:
            base += "_bifurcated"
        return re.sub(r"[^A-Za-z0-9_-]+", "_", base).strip("_") + extension

    def export_browse_csv(self) -> None:
        if not self._require_browse_page():
            return
        path = filedialog.asksaveasfilename(
            title="Export current page as CSV", defaultextension=".csv",
            initialfile=self._export_basename(".csv"),
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(self.browse_cols)
                for row in self.browse_rows:
                    writer.writerow([cell_text(row.get(c), 4000) for c in self.browse_cols])
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        self.log(f"{len(self.browse_rows)} row(s) exported to {path}", "ok")

    def export_browse_xlsx(self) -> None:
        if not self._require_browse_page():
            return
        mapping = self.selected_mapping()
        suggested = (mapping.source_table if mapping else "") or "Page"
        path = filedialog.asksaveasfilename(
            title="Export current page as Excel workbook", defaultextension=".xlsx",
            initialfile=self._export_basename(".xlsx"),
            filetypes=[("Excel workbook", "*.xlsx"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            write_xlsx_page(path, suggested, self.browse_cols, self.browse_rows)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        self.log(f"{len(self.browse_rows)} row(s) exported to {path}", "ok")

    def _default_sql_target(self) -> str:
        mapping = self.selected_mapping()
        idb = self.project.options.identity_db or "identity_db"
        if not mapping:
            return f"{idb}.export_page"
        if self.var_browse_dataset.get() == "Identity table only":
            return f"{idb}.{mapping.identity_table}"
        return f"{idb}.export_page"

    @staticmethod
    def _parse_sql_target(text: str) -> tuple[str, str]:
        """Return (quoted target, error). Accepts 'table' or 'database.table'."""
        raw = (text or "").strip().strip("`")
        if not raw:
            return "", "Enter a target table name."
        parts = [part.strip().strip("`") for part in raw.split(".")]
        if len(parts) > 2 or any(not part for part in parts):
            return "", "Use 'table' or 'database.table'."
        for part in parts:
            if not IDENT_NAME_RE.match(part):
                return "", (f"'{part}' is not a valid identifier "
                            "(1-64 chars of A-Z, a-z, 0-9, _ or $).")
        return ".".join(sql_ident(part) for part in parts), ""

    def export_browse_sql(self) -> None:
        if not self._require_browse_page():
            return
        mapping = self.selected_mapping()
        default = self._default_sql_target()
        target_text = self.prompt_text(
            "Export page as SQL INSERT",
            "Target table (the table must already exist)",
            default,
            hint=(f"Exported columns: {', '.join(self.browse_cols[:6])}"
                  + (" ..." if len(self.browse_cols) > 6 else "")
                  + "\nColumn names must match the target table. "
                    "Use database.table to qualify it."),
        )
        if not target_text:
            return
        target, error = self._parse_sql_target(target_text)
        if error:
            messagebox.showerror("Invalid target table", error)
            return

        header = [
            f"{APP_NAME} {APP_VERSION} - page export",
            f"Generated: {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Project: {self.project.name}",
            f"Source: {(mapping.key if mapping else '?')}  ({self.var_browse_dataset.get()})",
            f"Target: {target}",
            f"Rows: {len(self.browse_rows)}",
            "The target table must already exist with matching column names.",
            "Insert runs inside a transaction; COMMIT is at the end.",
        ]
        script = build_insert_script(target, self.browse_cols, self.browse_rows, header)

        path = filedialog.asksaveasfilename(
            title="Export current page as SQL INSERT", defaultextension=".sql",
            initialfile=self._export_basename(".sql"),
            filetypes=[("SQL script", "*.sql"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(script)
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        self.log(f"{len(self.browse_rows)} row(s) exported as INSERT statements to {path} "
                 f"(target {target})", "ok")

    # -- help --------------------------------------------------------------

    def _build_help_tab(self) -> None:
        frm = self.tab_help
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(0, weight=1)
        text = tk.Text(frm, wrap="word", font=("Segoe UI", 10), padx=14, pady=12)
        text.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(frm, orient="vertical", command=text.yview)
        sb.grid(row=0, column=1, sticky="ns")
        text.configure(yscrollcommand=sb.set)

        help_text = f"""{APP_NAME} {APP_VERSION}

WHAT IT DOES
  This is a guided five-step wizard. The sidebar shows where you are; use Next / Back,
  or click any step you have already reached.

  STEP 1  Connect
    Paste a full connection string, or press "Build connection string..." and fill in
    server address, port, username, password and database. The builder shows the
    generated string live. Then press Test & connect.

  STEP 2  Choose columns
    Browse databases and tables, tick the identity columns to hide, check the identity
    table / view names and the new identity database, then press Add / update mapping.

  STEP 3  Review
    See what will be created, read the warnings and export the .sql script if you want
    to run it elsewhere.

  STEP 4  Run
    Run the migration. Progress and results are logged live.

  STEP 5  Browse
    Inspect the joined view (or the identity table) and export the page to CSV, Excel
    or SQL INSERT.

  What the tool creates, in the NEW identity database:
    - a UUID surrogate key (primary key of the identity table)
    - the source primary key value(s), used as the link
    - the original identity values
    - metadata: source schema/table/columns, row hash, created_at, updated_at
    - a view joining the untouched source table to the identity rows, plus a second
      view with the identity columns removed

WHAT IS *NOT* MODIFIED
  The source table is read-only for this tool. No column is dropped, no value is
  overwritten, no row is deleted. Everything is written to the identity database.
  If you later want to actually remove the columns from the source table, do it
  yourself after you are happy with the result.

HOW THE LINK WORKS
  The identity table stores the source primary key (composite keys are supported,
  each PK column becomes a "_src_<name>" column) plus a UNIQUE index on it. That is
  what the views join on. One UUID per source row; re-running the migration keeps
  the existing UUID and only refreshes values whose hash changed.

RE-RUNNING
  - CREATE DATABASE / TABLE use IF NOT EXISTS.
  - Missing columns and the unique index are added through guarded ALTERs.
  - Data is loaded with UPDATE (changed rows only) and INSERT ... LEFT JOIN ...
    WHERE missing, so no duplicates are created.
  - The data phase runs inside a stored procedure with a ROLLBACK handler
    (or START TRANSACTION/COMMIT when the option is off).

EXPORTING A PAGE (Browse step)
  The "Export page" button writes the rows currently shown (after filtering) to:
  - CSV (.csv)      - UTF-8 with BOM so Excel opens it correctly.
  - Excel (.xlsx)   - no extra library needed; typed cells (numbers, dates,
                      decimals, NULL as an empty cell), frozen header row.
  - SQL INSERT (.sql) - asks for a target table (defaults to the identity table
                      when "Identity table only" is selected, otherwise
                      <identity_db>.export_page). The target table must already
                      exist and its column names must match the exported ones.
                      Values are fully escaped (quotes, backslashes, newlines,
                      NUL and Ctrl-Z) and NULLs are written as NULL. The script
                      sets utf8mb4 and wraps the INSERTs in START TRANSACTION /
                      COMMIT.
  Only the current page is written. Increase "Page size" first to export more.

REQUIRED PRIVILEGES
  Source server: SELECT on the source tables, plus CREATE / ALTER / CREATE ROUTINE
  on the identity database (and CREATE DATABASE if it does not exist yet).
  If CREATE ROUTINE is not allowed, untick the stored-procedure option.

SEPARATE SERVERS
  If the identity database lives on a different server, no SQL view can join the
  two sides. The app streams rows in batches and loads them into the identity
  server, and the Browse step joins the two sides in memory for the current page.
  The exported script then contains only the identity-side DDL.

SECURITY NOTES
  - Passwords are not written to project files unless you tick the option.
  - The identity values are stored as plain text: protect the identity database
    with grants, backups and access control.
  - The app never logs passwords.

CONNECTION STRING BUILDER (toolbox)
  Open it from Step 1 ("Build connection string...") or Tools > Connection string
  builder. Fill in:
    - Server address (host name or IP, e.g. 127.0.0.1 or db.example.com)
    - Port (3306 by default)
    - Username and password
    - Database: the schema that holds your tables. The table itself is chosen in
      Step 2. You may leave it empty to connect to the server only.
  The generated string updates as you type. Choose "mysql:// URL" (recommended; the
  password is URL-encoded) or "key=value". Use Copy to put it on the clipboard, or
  "Use this string" to drop it into the connection field.

SAMPLE CONNECTION STRINGS
  mysql://root:secret@127.0.0.1:3306/crm?charset=utf8mb4
  host=127.0.0.1;port=3306;user=root;password=secret;database=crm

TROUBLESHOOTING
  1146 table doesn't exist   -> run the migration first, then browse.
  1044/1045 access denied    -> check user, password and database grants.
  1305 procedure does not exist / 1227 -> no CREATE ROUTINE privilege; untick the
                                stored-procedure option in step 4 (Run).
  Duplicate key on _src_...  -> the source primary key changed type or the identity
                                table was created by an older version; inspect and
                                re-run, the tool will reuse existing rows by link.
"""
        text.insert("1.0", help_text)
        text.configure(state="disabled")


# ---------------------------------------------------------------------------
# Self test / CLI
# ---------------------------------------------------------------------------

def selftest() -> int:
    script = (
        "CREATE TABLE t (a int);\n"
        "DELIMITER $$\n"
        "CREATE PROCEDURE p()\nBEGIN\n  SELECT 1;\n  SELECT 2;\nEND$$\n"
        "DELIMITER ;\n"
        "CALL p();\n"
    )
    parts = split_sql_script(script)
    assert len(parts) == 3, f"splitter returned {len(parts)} statements: {parts}"
    assert parts[0].startswith("CREATE TABLE")
    assert "SELECT 2" in parts[1]

    project = demo_project()
    errors = validate_project(project)
    assert not errors, errors

    plan = build_plan(project)
    sql = plan.script_text
    for needle in (
        "CREATE DATABASE IF NOT EXISTS `crm_identity`",
        "CREATE TABLE IF NOT EXISTS `crm_identity`.`ident_customers`",
        "`_identity_uuid` char(36) NOT NULL",
        "UNIQUE KEY `uq_source_row` (`_src_id`)",
        "START TRANSACTION",
        "ROLLBACK",
        "CREATE OR REPLACE VIEW `crm_identity`.`v_customers_bifurcated`",
        "CREATE OR REPLACE VIEW `crm_identity`.`v_customers_pseudonymized`",
        "rows_without_identity",
        "COMMIT",
    ):
        assert needle in sql, f"missing in generated SQL: {needle}"
    assert "ALTER TABLE `crm`" not in sql, "script must never alter the source table"

    statements = split_sql_script(sql)
    assert len(statements) > 10, len(statements)
    for stmt in statements:
        if stmt.upper().startswith("ALTER TABLE"):
            assert "`crm_identity`" in stmt, f"ALTER outside identity DB: {stmt}"

    cross = demo_project()
    cross.options.same_server = False
    cross_plan = build_plan(cross)
    assert "CREATE OR REPLACE VIEW" not in cross_plan.script_text
    assert "streamed by the app" in cross_plan.script_text

    print(f"selftest OK - {len(statements)} statements in the demo script")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    if "--demo" in argv:
        sys.stdout.write(build_plan(demo_project()).script_text)
        return 0
    if "--uismoke" in argv:
        app = App()
        app.update_idletasks()
        app.update()
        print("UI OK")
        app.destroy()
        return 0
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

# Identity Bifurcation Tool

A single-file Python/Tkinter desktop app for **MySQL / MariaDB** that splits identity (PII)
columns out of a table into a **separate database**, linked by UUID, **without touching the
source table**.

![Step 1 - Connect](docs/screenshot-connection.png)

## What it produces

For each source table you map, the tool creates in the identity database:

| Object | Purpose |
| --- | --- |
| `ident_<table>` | One row per source row: `_identity_uuid` (UUID PK), the source PK as `_src_*`, the original identity values, `_row_hash`, `_source_schema`, `_source_table`, `_source_columns`, `_created_at`, `_updated_at` |
| `v_<table>_bifurcated` | View joining the untouched source row to its identity row (`idf_*` columns) |
| `v_<table>_pseudonymized` | View with the identity columns removed, keeping only the UUID |

Plus a re-runnable SQL script for the whole project.

The source table is **read-only** for this tool: no `ALTER`, `UPDATE`, `DELETE` or `DROP`
is ever issued against it.

## Requirements

* Windows, Python 3.9+ (Tkinter is bundled with the python.org installer)
* PyMySQL

```powershell
python -m pip install pymysql
```

## Run

```powershell
python identity_bifurcator.py
```

The app is a **five-step wizard**. The numbered sidebar shows where you are: finished steps
get a green tick, the current step is highlighted, and steps you have not reached yet are
locked. **Next** checks the current step before moving on; **Back** returns to the previous
one. **Guide & help** (or <kbd>F1</kbd>) opens the full reference without losing your place.

1. **Connect** – paste a full connection string, for example
   `mysql://root:secret@127.0.0.1:3306/crm?charset=utf8mb4`
   or `host=127.0.0.1;port=3306;user=root;password=secret;database=crm`.
   Press **Test & connect**, or build the string field by field with the
   [connection string builder](#connection-string-builder).
2. **Choose columns** – pick a database and table, tick the identity columns to hide
   (likely PII columns are pre-suggested), set the identity table/view names and the
   **new** identity database name, then **Add / update mapping**.
   Tables without a primary key are refused: the PK is how identity rows link back.
3. **Review** – press **Rebuild plan** (<kbd>F5</kbd>) to see the objects, warnings and the
   full script. Export it with **Export SQL...**.
4. **Run** – choose options and press **Run migration**. Progress is logged live and the
   wizard offers to jump to Browse when it finishes.
5. **Browse** – inspect the bifurcated view (or the identity table, or a client-side merge
   for separate servers), filter and page through it. **Export page** writes the rows
   currently shown as CSV, as an Excel workbook (`.xlsx`, no extra library needed) or as
   a SQL `INSERT` script for a target table you name.

![Choose columns](docs/screenshot-columns.png)

### Connection string builder

Step 1 has a **Build connection string...** button (also under *Tools*). Fill in the server
address, port, username, password and database and the string is generated as you type — no
need to remember the DSN syntax. Choose the `mysql://` URL format (recommended, the password
is URL-encoded) or `key=value`, then **Copy** it or press **Use this string** to drop it into
the connection field. The database is the schema holding your tables; the table itself is
picked in step 2.

![Connection string builder](docs/screenshot-builder.png)

Keyboard shortcuts: <kbd>F1</kbd> guide, <kbd>F5</kbd> rebuild plan, <kbd>Ctrl</kbd>+<kbd>N</kbd>
new project, <kbd>Ctrl</kbd>+<kbd>O</kbd> open, <kbd>Ctrl</kbd>+<kbd>S</kbd> save.

## Re-running

The generated script is idempotent:

* `CREATE DATABASE / TABLE IF NOT EXISTS`
* missing columns and the unique index are added through guarded `ALTER`s
* data load = `UPDATE` only rows whose hash changed + `INSERT ... LEFT JOIN ... WHERE missing`
* the data phase runs inside a stored procedure with a `ROLLBACK` handler
  (or `START TRANSACTION`/`COMMIT` when the option is off)

Existing UUIDs are preserved. Only values that actually changed are rewritten.

## Exporting a page

The **Export page** button in the Browse step exports exactly the rows on screen
(including the current search filter, and only the current page — raise *Page size* first
to export more). File names default to the table name plus the dataset, e.g.
`customers_bifurcated.xlsx`.

| Format | Notes |
| --- | --- |
| CSV | UTF-8 with BOM, opens cleanly in Excel |
| XLSX | Built directly as OOXML with `zipfile` — no `openpyxl` install. Numbers, dates and `DECIMAL`/`NULL` values keep their types; binary values are written as `0x…` hex; header row is frozen |
| SQL INSERT | Asks for a target table (`table` or `database.table`). The table must already exist with matching column names. Defaults to the identity table for *Identity table only*, otherwise `<identity_db>.export_page` |

The generated SQL sets `SET NAMES utf8mb4`, escapes quotes, backslashes, newlines, NUL and
Ctrl-Z, writes `NULL` for NULLs and wraps the batches in `START TRANSACTION` / `COMMIT`.

## Same server vs separate servers

* **Same server (default)** – one connection. Views join across the two databases, so the
  Browse step queries the view directly.
* **Separate servers** – tick the checkbox in step 1 and supply the identity
  server connection string (the **Build...** button opens the same builder for it). No SQL
  view can join servers, so the app streams rows in batches into the identity server and the
  Browse step joins the two sides in memory for the current page. The exported script then
  contains only identity-side DDL.

## Project files

**Save project** writes an `.idb.json` file containing the connection strings, options and
mappings (including a column-type snapshot, so a plan can be rebuilt offline).
Passwords are **not** written unless you tick *Store passwords inside the saved project
file*. When a project is opened without passwords, the app asks for them.

## CLI

```powershell
python identity_bifurcator.py --selftest   # splitter + SQL generator checks, prints the statement count
python identity_bifurcator.py --demo       # print the demo SQL to stdout
python identity_bifurcator.py --uismoke    # build the window and exit (smoke test)
```

## Required privileges

* Source server: `SELECT` on the source tables.
* Identity database: `CREATE`, `ALTER`, `CREATE ROUTINE` (only if the stored-procedure
  option is on) and `CREATE DATABASE` on the first run.

## Notes and limitations

* Identity values are stored **as plain text** in the identity database (no encryption).
  Protect that database with grants, backups and access control.
* The tool never secures or removes the original columns — that is a separate decision for
  you once you are happy with the identity copy.
* Cross-server mode requires the identity server to support the source column character
  sets and collations; otherwise create the identity tables with compatible types.
* MySQL 8.0.19+ uses the row-alias upsert syntax for the app-side batch load; older MySQL
  and MariaDB use `VALUES(...)`.
* Wide string primary keys may exceed InnoDB's 3072-byte index limit; the plan warns you.

## Troubleshooting

| Error | Meaning |
| --- | --- |
| 1045 Access denied | user/password/grants |
| 1046 No database selected | identity connection without a default DB while a temp table is used (fixed by the app; only relevant to hand-run SQL) |
| 1146 Table doesn't exist | views/tables not created yet – run the migration first |
| 1227 / 1305 routine errors | no `CREATE ROUTINE` privilege – untick the stored-procedure option |
| 1071 key too long | string PK too wide for the unique index |

![Browse and export](docs/screenshot-browse.png)

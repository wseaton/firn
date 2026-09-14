# firn (CLI)

Snowflake command line built for agents and scripts. Same `connections.toml`
as `snow`, but:

- **One Snowflake session across calls.** The session and master tokens are
  saved (0600) and reused; a dead session is renewed or re-created silently.
- **SSO once, MFA once.** Browser and MFA logins store the `idToken` /
  `mfaToken` Snowflake hands back (Keychain / Credential Manager, or the
  Python connector's `credential_cache_v1.json` on Linux) and replay them.
- **JSON when piped.** Rows as JSON lines on stdout, one metadata line with
  the `query_id` on stderr, structured errors, distinct exit codes.
- **Always-on log file**: one line per invocation, connection, session,
  and query at info; `-vv` for debug, `--trace` for HTTP detail. Secrets
  are redacted. `firn logs path` tells you where.
- **Headless** with `--headless`: prints the SSO URL instead of opening a
  browser.

```text
cargo install --path firn-cli
firn connection list
firn sql "SELECT current_user()"              # table on a TTY
firn sql "SELECT * FROM t WHERE id = ?" -b 7 | jq .   # jsonl when piped
firn --format csv sql -f report.sql > out.csv
firn sql --submit "CALL long_thing()"         # {"query_id": ...}
firn query wait <id> && firn query fetch <id>
firn auth status
```

## Connections

Resolved exactly like the official clients: `$SNOWFLAKE_HOME`, then
`~/.snowflake`, then the platform config dir; `connections.toml` first,
`[connections.*]` in `config.toml` second; `SNOWFLAKE_CONNECTIONS_<NAME>_<KEY>`
and `SNOWFLAKE_<KEY>` env overrides. `-c NAME` picks one,
`SNOWFLAKE_DEFAULT_CONNECTION_NAME` or `default_connection_name` otherwise.
`--warehouse/--database/--schema/--role` override the session context.

Supported authenticators: `snowflake` (password, optional `passcode`),
`username_password_mfa`, `snowflake_jwt` (`private_key_file`, optionally
`private_key_file_pwd`), `oauth`, `programmatic_access_token`,
`externalbrowser`.

Token caching is on unless `--no-cache` / `FIRN_NO_CACHE=true` or the
connection sets `client_store_temporary_credential = false`. Snowflake also
needs `ALLOW_ID_TOKEN` (SSO) or `ALLOW_CLIENT_MFA_CACHING` (MFA) on the
account.

## Output

| `--format` | stdout | stderr |
| --- | --- | --- |
| `jsonl` (default when piped) | one JSON object per row | one JSON line: `query_id`, `rows`, `columns`, context |
| `json` | `{"meta": {...}, "rows": [...]}` | nothing |
| `csv` | header + rows | metadata line |
| `table` (default on a TTY) | Unicode table fitted to the terminal: numbers right-aligned, NULLs dimmed, booleans and timestamps colored | `N rows, query_id ...`, the id linking to Snowsight query history in terminals with OSC 8 (Ghostty, Kitty, WezTerm, iTerm2) |

Errors go to stderr as `{"error": {"kind", "code", "message"}}` (or a plain
line in table mode). Colors and links appear only when stdout is a terminal
and `NO_COLOR` is unset, so piped output never carries escape codes.

| exit | meaning |
| --- | --- |
| 0 | ok |
| 1 | other |
| 2 | usage or config (bad flags, unknown connection, unreadable files) |
| 3 | auth (login failed, token problems) |
| 4 | Snowflake rejected or failed the statement |
| 5 | cancelled (Ctrl-C) or `--timeout` hit |

Ctrl-C cancels the running query server-side before exiting.

## Types

Rows use native types: `NUMBER(p, s)` as a JSON number with its scale
(`1.50`), timestamps as ISO 8601 (`TIMESTAMP_NTZ` without offset, `_LTZ`
and `_TZ` as the instant with `Z`), `DATE` and `TIME` as ISO strings,
`BINARY` as hex, `VECTOR` as an array. `VARIANT`, `OBJECT`, and `ARRAY`
arrive as JSON text.

## Binds and parameters

`-b VALUE` fills `?` placeholders in order. Integers, floats, `true`/`false`
and `null` are typed; a single-quoted value is text with the quotes removed;
anything else is text.

`--bind-json '[1, "a"]'` is the same positionally; `--bind-json '{"id": 1}'`
binds `:name` placeholders. A JSON array value becomes an array bind, so
`INSERT INTO t VALUES (?, ?)` with `--bind-json '[[1,2],["a","b"]]'`
inserts two rows in one statement. `--rows file.jsonl` (or `-`) does the
same from JSON Lines, one array per row:

```text
printf '[1,"a"]\n[2,"b"]\n' | firn sql "INSERT INTO t VALUES (?, ?)" --rows -
```

`-p KEY=VALUE` sets a session parameter for that statement only
(`QUERY_TAG`, `TIMEZONE`, ...).

## Stages

`firn stage put local.csv @my_stage/prefix/` gzips (unless the file is
already compressed or `--no-compress`) and client-side encrypts the file
exactly as the official drivers do, so Snowflake can `COPY INTO` from it
and other drivers can `GET` it. `firn stage get @my_stage/prefix/x.csv.gz
./out` downloads and decrypts. Both print the same per-file rows the
official clients show. S3-backed stages only for now.

## State on disk

| what | where | override |
| --- | --- | --- |
| sessions | `~/Library/Caches/firn/sessions`, `~/.cache/firn/sessions` | `FIRN_STATE_DIR` |
| logs | `~/Library/Application Support/firn/logs`, `~/.local/share/firn/logs` | `FIRN_LOG_DIR` |
| tokens | OS keychain, or `~/.cache/snowflake/credential_cache_v1.json` | `SF_TEMPORARY_CREDENTIAL_CACHE_DIR` |

`firn auth logout` closes and forgets the session; `--tokens` also drops the
cached id / MFA tokens.

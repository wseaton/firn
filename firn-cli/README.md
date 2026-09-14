# firn (CLI)

Snowflake command line for agents and scripts. It reads the same
`connections.toml` as `snow`, so `firn sql` replaces `snow sql` without
further setup.

![firn sql on a terminal: typed, colored table with a Snowsight query link](https://raw.githubusercontent.com/wseaton/firn/stable/firn-cli/assets/table.png)

## Why

A shell-driven caller (an agent, a CI job, a loop) invokes the CLI once per
query. With `snow` each invocation starts a Python interpreter and logs in
to Snowflake again; on SSO or MFA accounts that means a browser tab or a
push per call unless token caching is configured on both the account and
the client. Output is formatted for reading, so callers parse tables or
buffer a JSON array, and errors are text.

firn is one binary, a 9 MB download against the 88 MB RPM that ships
`snow` with its own Python, and differs in these ways:

One Snowflake session across calls. The session and master tokens are saved
(0600) and reused; a dead session is renewed or re-created.

SSO once, MFA once. Browser and MFA logins store the `idToken` / `mfaToken`
Snowflake returns (Keychain / Credential Manager, or the Python connector's
`credential_cache_v1.json` on Linux) and replay them. `--headless` prints the
SSO URL instead of opening a browser.

Output follows stdout. On a terminal `firn sql` prints a table fitted to
the window: numbers right-aligned, NULLs dimmed, timestamps and booleans
colored, query id linked to Snowsight query history. Piped, it prints JSON
lines with native types (numbers as numbers, timestamps as ISO 8601) for
`jq` and friends. Metadata and the `query_id` go to stderr, errors are
JSON, and exit codes separate usage, auth, and SQL failures. The same
command line serves the agent that parses it and the person who reruns it.

Async. `--submit` returns a `query_id` immediately; `query wait` and
`query fetch` pick it up later from any process. Ctrl-C cancels the query
server-side.

Log file. One line per invocation, connection, session, and query at
info; `-vv` for debug, `--trace` for HTTP detail. Secrets are redacted.
`firn logs path` prints the location.

## Compared to snow

| | `snow sql` | `firn sql` |
| --- | --- | --- |
| Install | 88 MB RPM / MSI / pip package with its own Python | 9 MB tarball, one binary |
| Login | every invocation | once; session reused across invocations, renewed when it expires |
| SSO / MFA | browser or push per invocation unless the connector's cache is set up | `idToken` / `mfaToken` cached and replayed; `--headless` prints the SSO URL |
| Piped output | `--format json` is one buffered array | JSON lines with native types; metadata and `query_id` on stderr |
| Errors | text | `{"error": {"kind", "code", "message"}}` and exit codes 2 / 3 / 4 / 5 |
| Parameters | client-side `-D key=value` text substitution | server-side binds: `-b`, `--bind-json`, `:name`, array binds, `--rows` from JSON lines |
| Long queries | blocks | `--submit` returns the id; `query status` / `wait` / `fetch` / `cancel` from any process; `--timeout` cancels server-side |
| Multi-statement | yes | `--multi [N]`, one result per statement |
| Schema only | | `--describe` returns column types without running the statement |
| Session params | | `-p QUERY_TAG=...` for one statement |
| Stages | `stage copy` on every cloud | `stage list` / `put` / `get`, S3-backed stages only |
| Logs | | every invocation, session, and query in a log file, secrets redacted |
| REPL, Snowpark, Streamlit, native apps, object commands | yes | no |

firn covers the query path: `sql`, `query`, `stage`, `connection`, `auth`.
Use `snow` for everything else; the two share `connections.toml` and, on
Linux, the token cache, so they coexist.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/wseaton/firn/stable/install.sh | sh
```

Installs the latest release to `~/.local/bin` (`FIRN_INSTALL_DIR` to change,
`FIRN_VERSION=0.1.2` to pin). Linux (x86_64, aarch64), macOS (Intel, Apple
silicon) and Windows archives, with a `SHA256SUMS` file, are on the
[releases page](https://github.com/wseaton/firn/releases?q=cli-v) under the
`cli-v*` tags. Or build from crates.io:

```sh
cargo install firn-cli
```

## Usage

```text
firn connection list
firn sql "SELECT current_user()"              # table on a TTY
firn sql "SELECT * FROM t WHERE id = ?" -b 7 | jq .   # jsonl when piped
firn --format csv sql -f report.sql > out.csv
firn sql --submit "CALL long_thing()"         # {"query_id": ...}
firn query wait <id> && firn query fetch <id>
firn auth status
```

![firn sql piped: JSON lines, async submit and wait](https://raw.githubusercontent.com/wseaton/firn/stable/firn-cli/assets/jsonl.png)

## Connections

firn reads the connection files the official clients write, so an existing
`snow` setup works as is. There is no `firn connection add`; write the file
by hand or use `snow connection add`. The file format is documented in
[Snowflake CLI: configure connections](https://docs.snowflake.com/en/developer-guide/snowflake-cli/connecting/configure-connections)
and the [config file reference](https://docs.snowflake.com/en/developer-guide/snowflake-cli/connecting/configure-cli).

Resolution order: `$SNOWFLAKE_HOME`, then `~/.snowflake`, then the platform
config dir; `connections.toml` first, `[connections.*]` in `config.toml`
second; `SNOWFLAKE_CONNECTIONS_<NAME>_<KEY>` and `SNOWFLAKE_<KEY>` env
overrides. `-c NAME` picks one, `SNOWFLAKE_DEFAULT_CONNECTION_NAME` or
`default_connection_name` otherwise. `--warehouse/--database/--schema/--role`
override the session context. The file must not be group or world writable.

`~/.snowflake/connections.toml`, one section per authenticator:

```toml
default_connection_name = "prod"

[prod]                                 # browser SSO (Okta, Entra, ...)
account = "myorg-myaccount"
user = "alice@example.com"
authenticator = "externalbrowser"
warehouse = "ANALYTICS"
role = "ANALYST"

[svc]                                  # key pair
account = "myorg-myaccount"
user = "SVC_ETL"
authenticator = "snowflake_jwt"
private_key_file = "/home/alice/.ssh/snowflake_rsa_key.p8"   # absolute path
private_key_file_pwd = "..."           # only for encrypted keys

[pat]                                  # programmatic access token
account = "myorg-myaccount"
user = "alice@example.com"
authenticator = "programmatic_access_token"
token = "..."

[mfa]                                  # password + Duo
account = "myorg-myaccount"
user = "alice@example.com"
authenticator = "username_password_mfa"
password = "..."

[oauth]
account = "myorg-myaccount"
user = "alice@example.com"
authenticator = "oauth"
token = "..."
```

`authenticator = "snowflake"` (or omitted) is plain password auth, with an
optional `passcode`. `token_file_path` reads the token from a file instead of
`token`. Then:

```text
firn connection list
firn connection show -c prod       # resolved values, secrets redacted
firn connection test -c prod       # logs in, prints the effective context
firn auth status                   # what is cached: session, id token, mfa token
```

Token caching is on unless `--no-cache` / `FIRN_NO_CACHE=true` or the
connection sets `client_store_temporary_credential = false`. Snowflake also
needs `ALLOW_ID_TOKEN` (SSO) or `ALLOW_CLIENT_MFA_CACHING` (MFA) on the
account. `--no-session` / `FIRN_NO_SESSION=true` logs in fresh each call.

## Output

| `--format` | stdout | stderr |
| --- | --- | --- |
| `jsonl` (default when piped) | one JSON object per row | one JSON line: `query_id`, `rows`, `columns`, context |
| `json` | `{"meta": {...}, "rows": [...]}` | nothing |
| `csv` | header + rows | metadata line |
| `table` (default on a TTY) | Unicode table fitted to the terminal: numbers right-aligned, NULLs dimmed, booleans and timestamps colored | `N rows, query_id ...`, the id linking to Snowsight query history in terminals with OSC 8 (Ghostty, Kitty, WezTerm, iTerm2) |

Errors go to stderr as `{"error": {"kind", "code", "message"}}` (or a plain
line in table mode). Colors and links appear only when stdout is a terminal
and `NO_COLOR` is unset (`--color always|never` overrides), so piped output
never carries escape codes. Table width follows the terminal, or `COLUMNS`
when set.

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

![firn stage put and get, and firn auth status](https://raw.githubusercontent.com/wseaton/firn/stable/firn-cli/assets/stage.png)

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

The screenshots are real Ghostty windows captured by
[`assets/render.sh`](./assets/render.sh) (macOS; needs Ghostty,
`GetWindowID`, and a connection).

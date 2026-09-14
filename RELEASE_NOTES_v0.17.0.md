# firn v0.17.0

Auth and configuration catch-up against gosnowflake v2.2.0, aimed at
short-lived processes (CLIs, agents) that must not log in on every call.

```toml
[dependencies]
firn = "0.17"
```

Default features: `cert-auth`. Optional: `browser-auth`, `keyring`, `polars`.

## Added

- `connections.toml` / `config.toml` loading with the shared client config
  spec: `SNOWFLAKE_HOME`, platform config dirs, `SNOWFLAKE_DEFAULT_CONNECTION_NAME`,
  `SNOWFLAKE_CONNECTIONS_<NAME>_<KEY>` overrides, `SNOWFLAKE_<KEY>` fallbacks,
  gosnowflake's file permission rules (`SnowflakeApi::from_connection`,
  `AuthArgs::from_connection`, `config::load_connection`, `ConnectionConfig`).
- `TokenCache` with `FileTokenCache` (Python connector `credential_cache_v1.json`
  layout), `KeyringTokenCache` (`keyring` feature), and `MemoryTokenCache`.
  Browser SSO replays the cached `idToken` (`AUTHENTICATOR=ID_TOKEN`); MFA
  replays the cached `mfaToken`. `SnowflakeApiBuilder::with_token_cache`,
  `with_default_token_cache`, `SnowflakeApi::clear_cached_credentials`.
- `SessionSnapshot`: `SnowflakeApi::session_snapshot` and
  `SnowflakeApiBuilder::with_session_snapshot` carry a live session between
  processes.
- Authenticators: `AuthType::ProgrammaticAccessToken`,
  `AuthType::UsernamePasswordMfa`, Duo `passcode` on `AuthType::Password`,
  passphrase-encrypted PKCS#8 private keys (`private_key_file_pwd`).
- `AuthArgs::base_url` and `host` / `port` / `protocol` / `region` config
  keys for private link, custom endpoints, and test servers.
- `SnowflakeApiBuilder::with_application` (`CLIENT_ENVIRONMENT.APPLICATION`,
  default `firn`).
- `tests/auth_flows.rs`: every login flow, token cache path, session
  hand-off, and mid-query renewal exercised against a local HTTP server.

- `firn-cli` workspace member: the `firn` binary (`sql`, `query`, `auth`,
  `connection`, `stage`, `logs`) built on the above.
- `SnowflakeApiBuilder::with_sso_url_handler` for headless browser SSO.
- `StatementType::{Insert, Update, Delete, Merge}`.
- The `snowflake-jwt` crate is vendored as `firn::jwt`; JWT lifetime is now
  59 minutes (Snowflake caps key-pair JWTs at one hour).

- `convert_batch`: decoded Arrow batches now carry native `Decimal128`,
  `Timestamp`, and `Time` columns instead of Snowflake's scaled ints and
  `{epoch, fraction}` structs.
- `StatementType::{Insert, Update, Delete, Merge}`.
- Login and query response bodies log at trace; debug gets one-line
  summaries (session id and validity, query id and row count).

- Binds: `QueryBuilder::bind_named` for `:name` placeholders, `Bind::array`
  for array binding (one statement, many rows), and `Bind::binary`,
  `date_millis`, `time_nanos`, `timestamp_*_nanos` constructors. Mixing
  named and positional binds is rejected before anything is sent.
- `ClientIdentity` on the builder; the default is now `Go/2.2.0`. Snowflake
  returns JSON instead of Arrow to client ids it does not recognize, so an
  honest `firn` identity is not the default.

- `GET`: stage downloads with decryption. `PUT` now gzips, encrypts
  (`x-amz-key` / `x-amz-iv` / `x-amz-matdesc`), honours `OVERWRITE`, and
  both return Snowflake's per-file result rows instead of an empty result.
  `transfer::{upload_file, download_file}` work against any `ObjectStore`.

## Fixed

- `execute_stream` on a DML / DDL result used to fail with
  `JsonStreamUnsupported` after the statement had already run; callers that
  fell back to `execute` ran it twice. JSON results now stream as one Utf8
  batch and the error variant is gone.

- A renew refused by Snowflake (killed session) falls back to a full login
  instead of failing the query.
- The login timeout now bounds the whole login, browser round-trips
  included; the SSO callback listener is async and stops when the login is
  cancelled instead of polling on a blocking thread for two minutes.

- Query submission now renews the session and retries on `390112`; before,
  only the polling paths did.
- `SNOWLFLAKE_WAREHOUSE` typo in `from_env`; it reads `SNOWFLAKE_WAREHOUSE`.
- Login and renew responses no longer print session, master, id, or MFA
  tokens in `Debug` output.

## Changed (breaking)

- `RawQueryData::Empty` is no longer returned for `PUT`; the result is JSON
  rows. `EncryptionMaterialVariant::Multiple` holds `Option`s.

- `AuthType` variants are struct-like (`Password { password, passcode }`,
  `Certificate { private_key_pem }`, `OAuth { token }`); `PasswordArgs`,
  `CertificateArgs`, `OAuthArgs` are gone. `AuthArgs` gained `base_url`.
- `SnowflakeApi::new(connection, session, account)` was removed; `Session`
  was never constructible outside the crate.
- `connection::Connection::request` takes a base `Url` instead of an account
  identifier.
- `AuthParts::session_token_auth_header` is an `Arc<str>`.

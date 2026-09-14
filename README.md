# firn

Rust client for Snowflake's internal HTTP API. Forked from
[andrusha/snowflake-rs](https://github.com/andrusha/snowflake-rs) /
[`snowflake-api`](https://crates.io/crates/snowflake-api) at v0.14.0.

- [`firn`](./snowflake-api) — published crate; client for the
  undocumented public API. See [`snowflake-api/README.md`](./snowflake-api/README.md)
  for features and usage. The key-pair JWT helper that upstream ships as
  `snowflake-jwt` is vendored here as `firn::jwt` (`cert-auth` feature).
- [`firn-cli`](./firn-cli) — the `firn` binary: a Snowflake CLI for agents
  with one session across calls, cached SSO / MFA tokens, JSON output, and
  an always-on log. See [`firn-cli/README.md`](./firn-cli/README.md).

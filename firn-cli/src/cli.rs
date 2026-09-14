use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Snowflake CLI built for agents: one session across calls, cached SSO and
/// MFA tokens, JSON output when piped, and an always-on log file.
#[derive(Parser, Debug)]
#[command(name = "firn", version, about, long_about = None)]
pub struct Cli {
    /// Connection name from connections.toml / config.toml
    /// (default: SNOWFLAKE_DEFAULT_CONNECTION_NAME, then default_connection_name)
    #[arg(short, long, global = true, env = "FIRN_CONNECTION")]
    pub connection: Option<String>,

    /// Output format. `auto` is jsonl when stdout is not a terminal, table otherwise.
    #[arg(long, global = true, env = "FIRN_FORMAT", default_value = "auto")]
    pub format: Format,

    /// Do not read or write the id / MFA token cache
    #[arg(long, global = true, env = "FIRN_NO_CACHE")]
    pub no_cache: bool,

    /// Do not reuse or persist the Snowflake session between invocations
    #[arg(long, global = true, env = "FIRN_NO_SESSION")]
    pub no_session: bool,

    /// Print the SSO URL to stderr instead of opening a browser
    #[arg(long, global = true, env = "FIRN_HEADLESS")]
    pub headless: bool,

    /// Stderr log verbosity: -v info, -vv debug, -vvv trace. The log file
    /// follows from debug upward and is otherwise at info.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Log HTTP-level detail to the log file
    #[arg(long, global = true, env = "FIRN_TRACE")]
    pub trace: bool,

    /// Login timeout in seconds (default 300, or the connection's login_timeout)
    #[arg(long, global = true, env = "FIRN_LOGIN_TIMEOUT")]
    pub login_timeout: Option<u64>,

    #[command(flatten)]
    pub context: ContextOverrides,

    #[command(subcommand)]
    pub command: Command,
}

/// Session context overrides applied on top of the connection.
#[derive(Args, Debug, Clone, Default)]
pub struct ContextOverrides {
    #[arg(long, global = true, env = "FIRN_WAREHOUSE")]
    pub warehouse: Option<String>,
    #[arg(long, global = true, env = "FIRN_DATABASE")]
    pub database: Option<String>,
    #[arg(long, global = true, env = "FIRN_SCHEMA")]
    pub schema: Option<String>,
    #[arg(long, global = true, env = "FIRN_ROLE")]
    pub role: Option<String>,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Auto,
    /// One JSON object per row on stdout; metadata as one JSON line on stderr
    Jsonl,
    /// One JSON document: metadata plus a `rows` array
    Json,
    Csv,
    Table,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run SQL from an argument, a file, or stdin
    Sql(SqlArgs),
    /// Inspect, wait for, fetch, or cancel a query by id
    #[command(subcommand)]
    Query(QueryCommand),
    /// Log in, inspect, or drop the cached session and tokens
    #[command(subcommand)]
    Auth(AuthCommand),
    /// List, show, or test configured connections
    #[command(subcommand)]
    Connection(ConnectionCommand),
    /// List or upload to a stage
    #[command(subcommand)]
    Stage(StageCommand),
    /// Log file location
    #[command(subcommand)]
    Logs(LogsCommand),
}

#[derive(Args, Debug)]
pub struct SqlArgs {
    /// SQL text. Omit to read from --file or stdin.
    pub query: Option<String>,

    /// Read SQL from a file (`-` for stdin)
    #[arg(short, long, conflicts_with = "query")]
    pub file: Option<PathBuf>,

    /// Positional `?` bind value. Repeat per placeholder. Integers, floats,
    /// `true`/`false`, and `null` are typed; anything else is text. Wrap in
    /// single quotes to force text.
    #[arg(short, long = "bind", value_name = "VALUE")]
    pub binds: Vec<String>,

    /// Binds as JSON: an array for positional `?` placeholders, an object
    /// for `:name` placeholders. Numbers, booleans, null, strings, and
    /// arrays (array binding) are typed from the JSON.
    #[arg(long, value_name = "JSON", conflicts_with = "binds")]
    pub bind_json: Option<String>,

    /// Array-bind rows from a JSON Lines file (`-` for stdin): each line is
    /// a JSON array with one value per `?`, so one statement inserts every row.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["binds", "bind_json"])]
    pub rows: Option<PathBuf>,

    /// Session parameter for this statement only, as KEY=VALUE (e.g. QUERY_TAG=agent-7)
    #[arg(short = 'p', long = "param", value_name = "KEY=VALUE")]
    pub params: Vec<String>,

    /// Run as a multi-statement payload. Optional exact statement count.
    #[arg(long, value_name = "COUNT", num_args = 0..=1, default_missing_value = "0")]
    pub multi: Option<u32>,

    /// Validate and return the result schema without executing
    #[arg(long, conflicts_with_all = ["multi", "submit"])]
    pub describe: bool,

    /// Submit without waiting; prints the query id. Follow up with `firn query wait/fetch`.
    #[arg(long, conflicts_with = "multi")]
    pub submit: bool,

    /// Give up (and cancel the query) after this many seconds
    #[arg(long, value_name = "SECONDS")]
    pub timeout: Option<u64>,
}

#[derive(Subcommand, Debug)]
pub enum QueryCommand {
    /// Current status of a query
    Status { query_id: String },
    /// Poll until the query reaches a terminal state
    Wait {
        query_id: String,
        /// Poll interval in seconds
        #[arg(long, default_value = "2")]
        interval: u64,
        /// Give up after this many seconds
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
    },
    /// Fetch the results of a finished query
    Fetch { query_id: String },
    /// Cancel a running query
    Cancel { query_id: String },
}

#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Log in now (ignoring any saved session) and save the session
    Login,
    /// Show what is cached for this connection
    Status,
    /// Close the saved session. With --tokens, also forget cached id / MFA tokens.
    Logout {
        #[arg(long)]
        tokens: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConnectionCommand {
    /// Names of every configured connection
    List,
    /// Resolved parameters of a connection, secrets redacted
    Show,
    /// Connect and report the effective account, user, role, warehouse, database, and schema
    Test,
}

#[derive(Subcommand, Debug)]
pub enum StageCommand {
    /// `LIST` a stage, e.g. `@my_stage/prefix`
    List { stage: String },
    /// `PUT` local files onto a stage (S3-backed stages). Globs are allowed.
    /// Files are gzipped unless already compressed and encrypted like the
    /// official drivers do.
    Put {
        local_path: String,
        stage: String,
        /// Upload as-is instead of gzipping (`AUTO_COMPRESS = FALSE`)
        #[arg(long)]
        no_compress: bool,
        /// Replace files that already exist on the stage
        #[arg(long)]
        overwrite: bool,
    },
    /// `GET` stage files into a local directory, decrypting them
    Get { stage: String, local_dir: PathBuf },
}

#[derive(Subcommand, Debug)]
pub enum LogsCommand {
    /// Print the log directory
    Path,
}

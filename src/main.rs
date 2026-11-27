//! `o1-netconfd-rs`: Memory-safe, crash-consistent Rust NETCONF server for O-RAN O1 / M-Plane.

pub mod datastore;
pub mod fault_proxy;
pub mod framing;
pub mod rpc;
pub mod ssh;

use anyhow::Result;
use clap::Parser;
use datastore::{DatastoreEngine, PersistedStore};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "o1-netconfd-rs", about = "Pure-Rust crash-safe NETCONF server with RFC 6470/5277 provenance")]
struct Cli {
    /// Listen address for NETCONF over SSH (RFC 6242)
    #[arg(long, default_value = "127.0.0.1:8831")]
    listen: String,

    /// Path to atomic JSON/WAL datastore file
    #[arg(long, default_value = "/tmp/o1-netconfd-rs/state.json")]
    state_file: PathBuf,

    /// Authorized user credentials in `user:password` format (repeatable)
    #[arg(long = "user", default_values_t = vec!["smo:smopass".to_string(), "ops2:ops2pass".to_string()])]
    users: Vec<String>,

    /// Enforce principal ownership on confirming/cancelling commits (mitigates T6 bearer-token hijack)
    #[arg(long, default_value_t = false)]
    strict_persist_owner: bool,

    /// Out-of-band oracle helper: print running XML from `state_file` and exit
    #[arg(long, default_value_t = false)]
    dump_running: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    if cli.dump_running {
        if cli.state_file.exists() {
            let store: PersistedStore = serde_json::from_str(&fs::read_to_string(&cli.state_file)?)?;
            println!("{}", datastore::render_cells_xml(&store.running_cells));
        } else {
            println!("<managed-element xmlns=\"urn:demo:o1:nrcelldu\"><NRCellDU><id>cell-1</id><attributes><administrativeState>LOCKED</administrativeState></attributes></NRCellDU></managed-element>");
        }
        return Ok(());
    }

    let mut user_map = HashMap::new();
    for entry in &cli.users {
        if let Some((u, p)) = entry.split_once(':') {
            user_map.insert(u.to_string(), p.to_string());
        }
    }

    let engine = DatastoreEngine::open(&cli.state_file, cli.strict_persist_owner)?;
    engine.spawn_timeout_watcher();

    tracing::info!(listen = %cli.listen, state = %cli.state_file.display(), "Starting o1-netconfd-rs");
    ssh::run_ssh_server(&cli.listen, engine, user_map).await
}

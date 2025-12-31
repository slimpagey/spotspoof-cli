mod ascii_spoof;
mod db;
mod http;
mod idn;
mod whois;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "spotspoof", version, about = "SpotSpoof CLI")]
struct Cli {
	#[command(subcommand)]
	command: Commands,
}

#[derive(Subcommand)]
enum Commands {
	/// Auto-detect ASCII vs IDN lookup
	Lookup {
		domain: String,
		#[arg(long)]
		db: Option<String>,
		#[arg(long)]
		json: bool,
	},
	/// ASCII spoof lookup
	Ascii {
		domain: String,
		#[arg(long)]
		db: Option<String>,
		#[arg(long)]
		json: bool,
	},
	/// IDN lookup
	Idn {
		domain: String,
		#[arg(long)]
		json: bool,
	},
	/// Import cleaned_domains.txt into SQLite (creates schema + indexes)
	Import {
		#[arg(long)]
		db: Option<String>,
		#[arg(long, default_value = "cleaned_domains.txt")]
		source: String,
		#[arg(long, default_value_t = 100000)]
		batch_size: usize,
		#[arg(long)]
		download: bool,
		#[arg(
			long,
			default_value = "https://github.com/slimpagey/spotspoof-cli/releases/latest/download/spotspoof.sqlite.zst"
		)]
		url: String,
	},
	/// Run an HTTP server for lookups
	Serve {
		#[arg(long, default_value = "127.0.0.1")]
		host: String,
		#[arg(long, default_value_t = 8080)]
		port: u16,
		#[arg(long)]
		db: Option<String>,
	},
}

#[tokio::main]
async fn main() -> Result<()> {
	let cli = Cli::parse();

	match cli.command {
		Commands::Lookup { domain, db, json } => {
			let db = resolve_db_path(db);
			// TODO: detect ASCII vs Puny based on input format.
			let is_idn = domain.starts_with("xn--") || domain.chars().any(|c| c as u32 > 127);
			if is_idn {
				let results = idn::lookup_idn(&domain)?;
				output("idn", json, &results)?;
			} else {
				let results = ascii_spoof::lookup_ascii(&domain, &db)?;
				output("ascii", json, &results)?;
			}
		}
		Commands::Ascii { domain, db, json } => {
			let db = resolve_db_path(db);
			let results = ascii_spoof::lookup_ascii(&domain, &db)?;
			output("ascii", json, &results)?;
		}
		Commands::Idn { domain, json } => {
			let results = idn::lookup_idn(&domain)?;
			output("idn", json, &results)?;
		}
		Commands::Import {
			db,
			source,
			batch_size,
			download,
			url,
		} => {
			let db = resolve_db_path(db);
			if download {
				db::download_db(&url, &db)?;
				println!("Downloaded database to {db}");
			} else {
				let imported = db::import_domains(&db, &source, batch_size)?;
				println!("Imported {imported} domains into {db}");
			}
		}
		Commands::Serve { host, port, db } => {
			let db = resolve_db_path(db);
			http::serve(host, port, db).await?;
		}
	}

	Ok(())
}

fn output(kind: &str, json: bool, payload: &serde_json::Value) -> Result<()> {
	if json {
		println!("{}", serde_json::to_string_pretty(payload)?);
		return Ok(());
	}
	println!("{kind} results:\n{}", serde_json::to_string_pretty(payload)?);
	Ok(())
}

fn resolve_db_path(db: Option<String>) -> String {
	if let Some(path) = db {
		return path;
	}
	if let Ok(exe) = std::env::current_exe() {
		if let Some(dir) = exe.parent() {
			return dir.join("spotspoof.sqlite").to_string_lossy().to_string();
		}
	}
	"spotspoof.sqlite".to_string()
}

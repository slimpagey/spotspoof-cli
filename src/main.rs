mod ascii_spoof;
mod db;
mod http;
mod idn;
mod types;
mod whois;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing::{error, info};
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::prelude::*;

use crate::types::{AsciiResponse, IdnResponse};

#[derive(Parser)]
#[command(
    name = "spotspoof",
    version,
    about = "SpotSpoof CLI",
    after_help = "Server:\n  spotspoof serve --host 127.0.0.1 --port 8080 --db spotspoof.sqlite [--no-db]\n  Routes: GET /, GET /healthz, POST /lookup, POST /ascii, POST /idn, GET /docs\n\nDB:\n  --no-db (lookup/ascii/serve) skips DB usage and returns empty ASCII results\n\nOutput:\n  (default) JSON\n  -t, --text\n  --csv\n  -o, --outfile <path>\n\nLogging:\n  --log-format <plain|json>\n  --log-destination <stdout|stderr|file>\n  --log-file <path> (required when --log-destination=file)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(
        long,
        value_enum,
        default_value = "plain",
        help = "Log output format (plain or json)"
    )]
    log_format: LogFormat,
    #[arg(
        long,
        value_enum,
        default_value = "stdout",
        help = "Log destination (stdout, stderr, or file)"
    )]
    log_destination: LogDestination,
    #[arg(long, help = "Log file path (required when --log-destination=file)")]
    log_file: Option<String>,
}

const DEFAULT_DB_URL: &str =
    "https://github.com/slimpagey/spotspoof-cli/releases/latest/spotspoof.sqlite.zst";

#[derive(Subcommand)]
enum Commands {
    /// Auto-detect ASCII vs IDN lookup
    Lookup {
        domain: String,
        #[arg(long)]
        db: Option<String>,
        #[arg(long, help = "Do not use or download the SQLite DB")]
        no_db: bool,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// ASCII spoof lookup
    Ascii {
        domain: String,
        #[arg(long)]
        db: Option<String>,
        #[arg(long, help = "Do not use or download the SQLite DB")]
        no_db: bool,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// IDN lookup
    Idn {
        domain: String,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Run an HTTP server for lookups
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 8080)]
        port: u16,
        #[arg(long)]
        db: Option<String>,
        #[arg(long, help = "Do not use or download the SQLite DB")]
        no_db: bool,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum LogFormat {
    Plain,
    Json,
}

#[derive(Copy, Clone, ValueEnum)]
enum LogDestination {
    Stdout,
    Stderr,
    File,
}

#[derive(Args, Clone)]
struct OutputArgs {
    #[arg(
		short = 't',
		long,
		help = "Output plain text",
		conflicts_with_all = ["csv"]
	)]
    text: bool,
    #[arg(long, help = "Output CSV", conflicts_with_all = ["text"])]
    csv: bool,
    #[arg(short = 'o', long, help = "Write output to a file instead of stdout")]
    outfile: Option<String>,
}

#[derive(Copy, Clone)]
enum OutputFormat {
    Json,
    Text,
    Csv,
}

#[derive(Clone)]
enum OutputData {
    Ascii(AsciiResponse),
    Idn(IdnResponse),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.log_format, cli.log_destination, cli.log_file.as_deref())?;

    match run(cli).await {
        Ok(()) => Ok(()),
        Err(err) => {
            error!("{err}");
            Err(err)
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Lookup {
            domain,
            db,
            no_db,
            output: output_args,
        } => {
            let db = resolve_db_path(db);
            let domain = crate::types::normalize_domain_input(&domain);
            let is_idn = domain.starts_with("xn--") || domain.chars().any(|c| c as u32 > 127);
            info!(kind = "lookup", domain = %domain, is_idn, db_path = %db);
            if is_idn {
                let results = idn::lookup_idn(&domain)?;
                output(
                    output_format(&output_args),
                    OutputData::Idn(results),
                    output_args.outfile.clone(),
                )?;
            } else {
                let results = if no_db {
                    crate::types::empty_ascii_response(&domain)
                } else {
                    db::ensure_db(&db, DEFAULT_DB_URL)?;
                    ascii_spoof::lookup_ascii(&domain, &db)?
                };
                output(
                    output_format(&output_args),
                    OutputData::Ascii(results),
                    output_args.outfile.clone(),
                )?;
            }
        }
        Commands::Ascii {
            domain,
            db,
            no_db,
            output: output_args,
        } => {
            let db = resolve_db_path(db);
            let domain = crate::types::normalize_domain_input(&domain);
            info!(kind = "ascii", domain = %domain, db_path = %db);
            let results = if no_db {
                crate::types::empty_ascii_response(&domain)
            } else {
                db::ensure_db(&db, DEFAULT_DB_URL)?;
                ascii_spoof::lookup_ascii(&domain, &db)?
            };
            output(
                output_format(&output_args),
                OutputData::Ascii(results),
                output_args.outfile.clone(),
            )?;
        }
        Commands::Idn {
            domain,
            output: output_args,
        } => {
            let domain = crate::types::normalize_domain_input(&domain);
            info!(kind = "idn", domain = %domain);
            let results = idn::lookup_idn(&domain)?;
            output(
                output_format(&output_args),
                OutputData::Idn(results),
                output_args.outfile.clone(),
            )?;
        }
        Commands::Serve {
            host,
            port,
            db,
            no_db,
        } => {
            let db = resolve_db_path(db);
            info!(kind = "serve", host = %host, port, db_path = %db);
            if !no_db {
                db::ensure_db(&db, DEFAULT_DB_URL)?;
            }
            http::serve(host, port, db, !no_db).await?;
        }
    }

    Ok(())
}

fn output(format: OutputFormat, payload: OutputData, outfile: Option<String>) -> Result<()> {
    validate_output(&payload)?;
    let rendered = format_output(format, payload)?;
    write_output(rendered, outfile)?;
    Ok(())
}

fn write_output(output: String, destination: Option<String>) -> Result<()> {
    if let Some(path) = destination {
        std::fs::write(path, output)?;
    } else {
        println!("{output}");
    }
    Ok(())
}

fn validate_output(payload: &OutputData) -> Result<()> {
    match payload {
        OutputData::Ascii(data) => crate::types::validate_ascii_response(data),
        OutputData::Idn(data) => crate::types::validate_idn_response(data),
    }
}

fn format_output(format: OutputFormat, payload: OutputData) -> Result<String> {
    match format {
        OutputFormat::Json => match payload {
            OutputData::Ascii(data) => Ok(serde_json::to_string_pretty(&data)?),
            OutputData::Idn(data) => Ok(serde_json::to_string_pretty(&data)?),
        },
        OutputFormat::Text => format_text(payload),
        OutputFormat::Csv => format_csv(payload),
    }
}

fn format_text(payload: OutputData) -> Result<String> {
    match payload {
        OutputData::Ascii(data) => Ok(format_ascii_text(&data.results)),
        OutputData::Idn(data) => Ok(format_idn_text(&data.results)),
    }
}

fn format_csv(payload: OutputData) -> Result<String> {
    match payload {
        OutputData::Ascii(data) => format_ascii_csv(&data.results),
        OutputData::Idn(data) => format_idn_csv(&data.results),
    }
}

fn format_ascii_text(results: &[crate::types::AsciiResult]) -> String {
    if results.is_empty() {
        return "No results".to_string();
    }
    results
        .iter()
        .map(|result| {
            format!(
                "Domain: {}, Similarity: {}",
                result.domain, result.similarity
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn format_idn_text(results: &[crate::types::IdnResult]) -> String {
    if results.is_empty() {
        return "No results".to_string();
    }
    results
        .iter()
        .map(|result| {
            let mapping_text = if result.mappings.is_empty() {
                "(none)".to_string()
            } else {
                result
                    .mappings
                    .iter()
                    .map(|mapping| format!("{} -> {}", mapping.ascii, mapping.unicode))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            format!("Domain: {}, Mappings: {mapping_text}", result.domain)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn format_ascii_csv(results: &[crate::types::AsciiResult]) -> Result<String> {
    let mut writer = csv::WriterBuilder::new().from_writer(vec![]);
    writer.write_record(["domain", "similarity"])?;
    for result in results {
        writer.write_record([result.domain.as_str(), &result.similarity.to_string()])?;
    }
    let data = writer.into_inner()?;
    Ok(String::from_utf8(data)
        .unwrap_or_default()
        .trim_end()
        .to_string())
}

fn format_idn_csv(results: &[crate::types::IdnResult]) -> Result<String> {
    let mut writer = csv::WriterBuilder::new().from_writer(vec![]);
    writer.write_record(["domain", "mappings"])?;
    for result in results {
        let mapping_text = result
            .mappings
            .iter()
            .map(|mapping| format!("{}->{}", mapping.ascii, mapping.unicode))
            .collect::<Vec<_>>()
            .join("|");
        writer.write_record([result.domain.as_str(), mapping_text.as_str()])?;
    }
    let data = writer.into_inner()?;
    Ok(String::from_utf8(data)
        .unwrap_or_default()
        .trim_end()
        .to_string())
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

fn output_format(args: &OutputArgs) -> OutputFormat {
    if args.text {
        return OutputFormat::Text;
    }
    if args.csv {
        return OutputFormat::Csv;
    }
    OutputFormat::Json
}

fn init_logging(
    format: LogFormat,
    destination: LogDestination,
    log_file: Option<&str>,
) -> Result<()> {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let writer: BoxMakeWriter = match destination {
        LogDestination::Stdout => BoxMakeWriter::new(std::io::stdout),
        LogDestination::Stderr => BoxMakeWriter::new(std::io::stderr),
        LogDestination::File => {
            let path = log_file.ok_or_else(|| {
                anyhow::anyhow!("--log-file is required when --log-destination=file")
            })?;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            BoxMakeWriter::new(file)
        }
    };

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_target(false)
        .with_file(true)
        .with_line_number(true);

    let fmt_layer = match format {
        LogFormat::Plain => fmt_layer.boxed(),
        LogFormat::Json => fmt_layer.json().boxed(),
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .try_init()
        .map_err(|err| anyhow::anyhow!(err))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_logging_requires_file_path_for_file_destination() {
        let err = init_logging(LogFormat::Plain, LogDestination::File, None).unwrap_err();
        assert!(err
            .to_string()
            .contains("--log-file is required when --log-destination=file"));
    }

    #[test]
    fn format_ascii_text_output() {
        let payload = OutputData::Ascii(AsciiResponse {
            q: "gooble.com".to_string(),
            ascii: true,
            puny: false,
            results: vec![crate::types::AsciiResult {
                domain: "google.com".to_string(),
                similarity: 90,
            }],
        });
        let text = format_output(OutputFormat::Text, payload).unwrap();
        assert_eq!(text, "Domain: google.com, Similarity: 90");
    }

    #[test]
    fn format_idn_text_output() {
        let payload = OutputData::Idn(IdnResponse {
            q: "амаzоn.com".to_string(),
            ascii: false,
            puny: true,
            results: vec![crate::types::IdnResult {
                domain: "amazon.com".to_string(),
                is_registered: true,
                mappings: vec![crate::types::PunyMapping {
                    ascii: "a".to_string(),
                    unicode: "а".to_string(),
                }],
            }],
        });
        let text = format_output(OutputFormat::Text, payload).unwrap();
        assert_eq!(text, "Domain: amazon.com, Mappings: a -> а");
    }

    #[test]
    fn format_ascii_csv_output() {
        let payload = OutputData::Ascii(AsciiResponse {
            q: "gooble.com".to_string(),
            ascii: true,
            puny: false,
            results: vec![
                crate::types::AsciiResult {
                    domain: "google.com".to_string(),
                    similarity: 90,
                },
                crate::types::AsciiResult {
                    domain: "g00gle.com".to_string(),
                    similarity: 88,
                },
            ],
        });
        let csv = format_output(OutputFormat::Csv, payload).unwrap();
        assert_eq!(csv, "domain,similarity\ngoogle.com,90\ng00gle.com,88");
    }

    #[test]
    fn write_output_to_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("spotspoof-output-test.txt");
        let path_str = path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);

        write_output("hello".to_string(), Some(path_str.clone())).unwrap();
        let contents = std::fs::read_to_string(&path_str).unwrap();
        assert_eq!(contents, "hello");

        let _ = std::fs::remove_file(&path_str);
    }
}

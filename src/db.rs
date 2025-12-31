use anyhow::Result;
use rusqlite::{params, Connection, Transaction};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};

const DEFAULT_DB_SHA256_PATH: &str = "config/db_sha256.txt";

pub fn open(path: &str) -> Result<Connection> {
	let conn = Connection::open(path)?;
	Ok(conn)
}

pub fn fetch_candidates(
	conn: &Connection,
	first_char: char,
	min_len: usize,
	max_len: usize,
	limit: usize,
) -> Result<Vec<String>> {
	let mut stmt = conn.prepare(
		"SELECT domain FROM legit_domains WHERE first_char = ?1 AND length >= ?2 AND length <= ?3 LIMIT ?4",
	)?;
	let rows = stmt.query_map(
		(
			first_char.to_string(),
			min_len as i64,
			max_len as i64,
			limit as i64,
		),
		|row| row.get::<_, String>(0),
	)?;

	let mut out = Vec::new();
	for row in rows {
		out.push(row?);
	}
	Ok(out)
}

pub fn import_domains(db_path: &str, source_path: &str, batch_size: usize) -> Result<usize> {
	let mut conn = open(db_path)?;
	init_schema(&conn)?;

	let file = File::open(source_path)?;
	let reader = BufReader::new(file);

	let mut imported = 0usize;
	let mut batch: Vec<String> = Vec::with_capacity(batch_size);

	for line in reader.lines() {
		let line = line?;
		let domain = line.trim().to_lowercase();
		if domain.is_empty() {
			continue;
		}
		if !should_include(&domain) {
			continue;
		}
		batch.push(domain);
		if batch.len() >= batch_size {
			imported += insert_batch(&mut conn, &batch)?;
			batch.clear();
		}
	}

	if !batch.is_empty() {
		imported += insert_batch(&mut conn, &batch)?;
	}

	Ok(imported)
}

pub fn download_db(url: &str, db_path: &str) -> Result<()> {
	if let Some(parent) = std::path::Path::new(db_path).parent() {
		if !parent.as_os_str().is_empty() {
			fs::create_dir_all(parent)?;
		}
	}

	let response = reqwest::blocking::get(url)?;
	if !response.status().is_success() {
		return Err(anyhow::anyhow!(
			"Download failed: HTTP {}",
			response.status()
		));
	}

	let compressed = response.bytes()?;
	verify_db_sha256(&compressed)?;

	let tmp_path = format!("{db_path}.tmp");
	let mut decoder = zstd::stream::read::Decoder::new(std::io::Cursor::new(compressed))?;
	let mut out = File::create(&tmp_path)?;
	std::io::copy(&mut decoder, &mut out)?;
	out.flush()?;
	fs::rename(tmp_path, db_path)?;
	Ok(())
}

fn init_schema(conn: &Connection) -> Result<()> {
	conn.execute_batch(
		"CREATE TABLE IF NOT EXISTS legit_domains (
			domain TEXT PRIMARY KEY,
			first_char TEXT NOT NULL,
			length INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_legit_char_len
			ON legit_domains(first_char, length);",
	)?;
	Ok(())
}

fn insert_batch(conn: &mut Connection, batch: &[String]) -> Result<usize> {
	let tx = conn.transaction()?;
	let inserted = insert_batch_tx(&tx, batch)?;
	tx.commit()?;
	Ok(inserted)
}

fn insert_batch_tx(tx: &Transaction, batch: &[String]) -> Result<usize> {
	let mut stmt = tx.prepare(
		"INSERT OR IGNORE INTO legit_domains (domain, first_char, length) VALUES (?1, ?2, ?3)",
	)?;
	let mut count = 0usize;
	for domain in batch {
		let first_char = domain.chars().next().unwrap_or('-').to_string();
		let len = domain.len() as i64;
		stmt.execute(params![domain, first_char, len])?;
		count += 1;
	}
	Ok(count)
}

fn should_include(domain: &str) -> bool {
	const MAX_DOMAIN_LENGTH: usize = 15;
	if domain.len() > MAX_DOMAIN_LENGTH {
		return false;
	}
	let first = domain.chars().next().unwrap_or('\0');
	if matches!(first, 'q' | 'x' | 'z' | '0'..='9') {
		return false;
	}
	true
}

fn read_expected_db_sha256() -> Result<String> {
	let mut candidates = Vec::new();
	if let Ok(path) = std::env::var("SPOTSPOOF_DB_SHA256_PATH") {
		candidates.push(path);
	}
	if let Ok(exe) = std::env::current_exe() {
		if let Some(dir) = exe.parent() {
			candidates.push(dir.join(DEFAULT_DB_SHA256_PATH).to_string_lossy().to_string());
		}
	}
	candidates.push(DEFAULT_DB_SHA256_PATH.to_string());

	let mut last_err = None;
	let mut contents = String::new();
	for path in candidates {
		match File::open(&path) {
			Ok(mut file) => {
				file.read_to_string(&mut contents)?;
				return Ok(contents.trim().to_lowercase());
			}
			Err(err) => last_err = Some(err),
		}
	}
	let err = last_err.unwrap_or_else(|| std::io::Error::new(
		std::io::ErrorKind::NotFound,
		"DB checksum file not found",
	));
	return Err(err.into());
}

fn verify_db_sha256(compressed: &[u8]) -> Result<()> {
	let expected = read_expected_db_sha256()?;
	let mut hasher = Sha256::new();
	hasher.update(compressed);
	let actual = format!("{:x}", hasher.finalize());
	if actual != expected {
		return Err(anyhow::anyhow!(
			"DB checksum mismatch: expected {expected}, got {actual}"
		));
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs::File;
	use std::io::Write;
	use std::io::{Read};
	use std::net::TcpListener;
	use std::thread;
	use std::time::{SystemTime, UNIX_EPOCH};
	use std::sync::Mutex;

	static ENV_LOCK: Mutex<()> = Mutex::new(());

	fn tmp_path(name: &str) -> String {
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_millis();
		let mut path = std::env::temp_dir();
		path.push(format!("spotspoof-cli-{name}-{now}.sqlite"));
		path.to_string_lossy().to_string()
	}

	#[test]
	fn import_and_fetch_candidates_round_trip() {
		let db_path = tmp_path("import");
		let source_path = tmp_path("domains");

		let mut file = File::create(&source_path).expect("source file");
		writeln!(file, "amazon.com").unwrap();
		writeln!(file, "xray.com").unwrap();
		writeln!(file, "verylongdomainnamethatislong.com").unwrap();

		let imported = import_domains(&db_path, &source_path, 2).expect("import should succeed");
		assert_eq!(imported, 1);

		let conn = open(&db_path).expect("open should succeed");
		let results = fetch_candidates(&conn, 'a', 1, 20, 10).expect("fetch should succeed");
		assert_eq!(results, vec!["amazon.com".to_string()]);

		let _ = fs::remove_file(&db_path);
		let _ = fs::remove_file(&source_path);
	}

	#[test]
	fn should_include_filters_disallowed_domains() {
		assert!(should_include("amazon.com"));
		assert!(!should_include("xray.com"));
		assert!(!should_include("9bad.com"));
		assert!(!should_include("averyveryverylongdomain.com"));
	}

	fn start_server(response: Vec<u8>, expected_method: &str, expected_path: &str) -> String {
		let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
		let addr = listener.local_addr().expect("addr");
		let expected_method = expected_method.to_string();
		let expected_path = expected_path.to_string();
		thread::spawn(move || {
			if let Ok((mut stream, _)) = listener.accept() {
				let mut buf = [0u8; 1024];
				let read = stream.read(&mut buf).unwrap_or(0);
				let request = String::from_utf8_lossy(&buf[..read]);
				let ok = request
					.lines()
					.next()
					.map(|line| line.starts_with(&format!("{expected_method} {expected_path} ")))
					.unwrap_or(false);
				if ok {
					let _ = stream.write_all(&response);
				} else {
					let _ = stream.write_all(
						b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
					);
				}
			}
		});
		format!("http://{addr}/db.zst")
	}

	#[test]
	fn download_db_writes_decompressed_file() {
		let _guard = ENV_LOCK.lock().unwrap();
		let db_path = tmp_path("download");
		let body = zstd::stream::encode_all("hello".as_bytes(), 0).expect("compress");
		let mut hasher = Sha256::new();
		hasher.update(&body);
		let hash = format!("{:x}", hasher.finalize());
		let sha_path = tmp_path("sha256");
		fs::write(&sha_path, hash).expect("write sha");
		std::env::set_var("SPOTSPOOF_DB_SHA256_PATH", &sha_path);

		let response = [
			format!(
				"HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
				body.len()
			)
			.into_bytes(),
			body,
		]
		.concat();
		let url = start_server(response, "GET", "/db.zst");

		download_db(&url, &db_path).expect("download should succeed");
		let contents = fs::read(&db_path).expect("read db");
		assert_eq!(contents, b"hello");

		let _ = fs::remove_file(&db_path);
		let _ = fs::remove_file(&sha_path);
		std::env::remove_var("SPOTSPOOF_DB_SHA256_PATH");
	}
}

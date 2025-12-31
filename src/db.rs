use anyhow::Result;
use rusqlite::{params, Connection, Transaction};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};

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

	let tmp_path = format!("{db_path}.tmp");
	let mut decoder = zstd::stream::read::Decoder::new(response)?;
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

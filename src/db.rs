/*
SQLite database utilities. Handles opening the local DB, verifying the downloaded
compressed DB via SHA-256, and downloading/unpacking the release database when needed.
*/
use anyhow::Result;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};

const DEFAULT_DB_SHA256_PATH: &str = "config/db_sha256.txt";
const EMBEDDED_DB_SHA256: &str = include_str!("../config/db_sha256.txt");
pub const DEFAULT_DB_URL: &str =
    "https://github.com/slimpagey/spotspoof-cli/releases/latest/download/spotspoof.sqlite.zst";

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

pub fn ensure_db(db_path: &str, url: &str) -> Result<()> {
    let path = std::path::Path::new(db_path);
    if !path.exists() {
        return download_db(url, db_path);
    }

    let conn = match open(db_path) {
        Ok(conn) => conn,
        Err(_) => return download_db(url, db_path),
    };
    let mut stmt = match conn.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='legit_domains' LIMIT 1",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return download_db(url, db_path),
    };
    let mut rows = match stmt.query([]) {
        Ok(rows) => rows,
        Err(_) => return download_db(url, db_path),
    };
    if rows.next()?.is_none() {
        return download_db(url, db_path);
    }

    Ok(())
}

fn read_expected_db_sha256() -> Result<String> {
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var("SPOTSPOOF_DB_SHA256_PATH") {
        candidates.push(path);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(
                dir.join(DEFAULT_DB_SHA256_PATH)
                    .to_string_lossy()
                    .to_string(),
            );
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
    if !EMBEDDED_DB_SHA256.trim().is_empty() {
        return Ok(EMBEDDED_DB_SHA256.trim().to_lowercase());
    }
    let err = last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "DB checksum file not found")
    });
    Err(err.into())
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
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

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
                    let _ =
                        stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
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
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(),
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

    #[test]
    #[ignore = "slow: downloads the release DB and requires network access"]
    fn release_db_download_matches_sha256() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SPOTSPOOF_DB_SHA256_PATH");

        let mut response = reqwest::blocking::get(DEFAULT_DB_URL).expect("download release db");
        if !response.status().is_success() {
            panic!("Download failed: HTTP {}", response.status());
        }

        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut total = 0usize;
        loop {
            let read = response.read(&mut buf).expect("read response");
            if read == 0 {
                break;
            }
            total += read;
            hasher.update(&buf[..read]);
        }

        let expected = read_expected_db_sha256().expect("read expected sha");
        let actual = format!("{:x}", hasher.finalize());
        assert!(total > 0, "expected response body, downloaded 0 bytes");
        assert_eq!(actual, expected, "release DB checksum mismatch");
    }
}

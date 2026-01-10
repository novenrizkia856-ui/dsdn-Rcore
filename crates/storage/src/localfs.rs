use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use std::io::{Write, Read};
use std::error::Error;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::store::Storage;
use dsdn_common::Result;

/// Local filesystem backend
#[derive(Clone, Debug)]
pub struct LocalFsStorage {
    #[allow(dead_code)]
    base: PathBuf,
    objects_dir: PathBuf,
}

#[derive(Debug)]
pub enum LocalFsError {
    Io(std::io::Error),
    InvalidHash,
}

impl fmt::Display for LocalFsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LocalFsError::Io(e) => write!(f, "io error: {}", e),
            LocalFsError::InvalidHash => write!(f, "invalid hash"),
        }
    }
}

impl Error for LocalFsError {}

impl From<std::io::Error> for LocalFsError {
    fn from(e: std::io::Error) -> Self {
        LocalFsError::Io(e)
    }
}

impl LocalFsStorage {
    /// Create new localfs backend rooted at base_dir.
    /// It will create base_dir/objects if missing.
    pub fn new(base_dir: impl AsRef<Path>) -> Result<Self> {
        let base = base_dir.as_ref().to_path_buf();
        let objects_dir = base.join("objects");
        // map std::io::Error into the boxed error type expected by dsdn_common::Result
        fs::create_dir_all(&objects_dir).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        Ok(LocalFsStorage { base, objects_dir })
    }

    /// Compute object path for a given hash: objects/<first2>/<hash>
    fn object_path(&self, hash: &str) -> Result<PathBuf> {
        if hash.len() < 2 {
            return Err(Box::new(LocalFsError::InvalidHash));
        }
        let prefix = &hash[0..2];
        let dir = self.objects_dir.join(prefix);
        Ok(dir.join(hash))
    }

    /// Atomic write: write to temp file then rename
    fn atomic_write(&self, dest: &Path, data: &[u8]) -> Result<()> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        }
        // temp file name: dest.tmp.<timestamp>
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        let tmp = dest.with_extension(format!("tmp.{}", ts));
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
            f.write_all(data).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
            f.sync_all().map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        }
        fs::rename(&tmp, dest).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        Ok(())
    }
}

impl Storage for LocalFsStorage {
    fn put_chunk(&self, hash: &str, data: &[u8]) -> dsdn_common::Result<()> {
        // object_path already returns dsdn_common::Result, so just use ?
        let path = self.object_path(hash)?;
        // if already exists, do nothing (idempotent)
        if path.exists() {
            return Ok(());
        }
        self.atomic_write(&path, data)?;
        Ok(())
    }

    fn get_chunk(&self, hash: &str) -> dsdn_common::Result<Option<Vec<u8>>> {
        let path = self.object_path(hash)?;
        if !path.exists() {
            return Ok(None);
        }
        let mut f = File::open(&path).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        Ok(Some(buf))
    }

    fn has_chunk(&self, hash: &str) -> dsdn_common::Result<bool> {
        let path = self.object_path(hash)?;
        Ok(path.exists())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::chunker;
    use dsdn_common::cid::sha256_hex;

    #[test]
    fn test_localfs_put_get_has() {
        let tmp = TempDir::new().expect("tmpdir");
        let store = LocalFsStorage::new(tmp.path()).expect("new store");

        // sample data
        let data = b"this is a test chunk";
        let hash = sha256_hex(data);

        assert!(!store.has_chunk(&hash).expect("has check"));
        store.put_chunk(&hash, data).expect("put");
        assert!(store.has_chunk(&hash).expect("has after put"));
        let got = store.get_chunk(&hash).expect("get").expect("exists");
        assert_eq!(got.as_slice(), data);
    }

    #[test]
    fn test_localfs_atomic_put_idempotent() {
        let tmp = TempDir::new().expect("tmpdir2");
        let store = LocalFsStorage::new(tmp.path()).expect("new store");

        let data1 = b"v1";
        let data2 = b"v2";
        let h1 = sha256_hex(data1);

        store.put_chunk(&h1, data1).expect("put1");
        // second put with same hash but different data should be no-op (we treat existing as authoritative)
        store.put_chunk(&h1, data2).expect("put2");
        let got = store.get_chunk(&h1).expect("get").expect("exists");
        assert_eq!(got.as_slice(), data1);
    }

    #[test]
    fn test_chunking_and_store_integration() {
        let tmp = TempDir::new().expect("tmpdir3");
        let store = LocalFsStorage::new(tmp.path()).expect("new store");

        // create a synthetic large buffer (but small for test)
        let data = vec![0u8; 1024 * 5 + 10]; // 5 KiB + 10
        let mut reader: &[u8] = &data;
        let chunks = chunker::chunk_reader(&mut reader, 1024).expect("chunks");
        assert!(chunks.len() > 1);

        // store all chunks
        for c in &chunks {
            let h = sha256_hex(c);
            store.put_chunk(&h, c).expect("put chunk");
            let got = store.get_chunk(&h).expect("get chunk").expect("exists");
            assert_eq!(&got, c);
        }
    }
}
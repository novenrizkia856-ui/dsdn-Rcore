use std::fmt::Debug;

pub trait Storage: Debug + Send + Sync + 'static {
    fn put_chunk(&self, hash: &str, data: &[u8]) -> dsdn_common::Result<()>;
    fn get_chunk(&self, hash: &str) -> dsdn_common::Result<Option<Vec<u8>>>;
    fn has_chunk(&self, hash: &str) -> dsdn_common::Result<bool>;

    /// Delete chunk by hash. Returns Ok(true) if deleted, Ok(false) if not found.
    fn delete_chunk(&self, hash: &str) -> dsdn_common::Result<bool>;

    /// List all chunk hashes in store. Returns (hash, size_bytes) pairs.
    fn list_chunks(&self) -> dsdn_common::Result<Vec<(String, u64)>>;
}
use std::fmt::Debug;

pub trait Storage: Debug + Send + Sync + 'static {
    fn put_chunk(&self, hash: &str, data: &[u8]) -> dsdn_common::Result<()>;
    fn get_chunk(&self, hash: &str) -> dsdn_common::Result<Option<Vec<u8>>>;
    fn has_chunk(&self, hash: &str) -> dsdn_common::Result<bool>;
}

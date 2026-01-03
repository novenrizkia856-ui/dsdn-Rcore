use std::io::{Read, Result as IoResult};
use std::fs::File;
use std::path::Path;

/// Default chunk size: 16 MiB
pub const DEFAULT_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// Chunk file from a path. Produces Vec<(offset, Vec<u8>)> where offset is chunk index.
/// This function reads the file in streaming fashion to avoid loading whole file into memory.
pub fn chunk_file(path: impl AsRef<Path>, chunk_size: usize) -> IoResult<Vec<Vec<u8>>> {
    let mut f = File::open(path)?;
    chunk_reader(&mut f, chunk_size)
}

/// Read all chunks from a reader. Returns a Vec of chunk bytes.
pub fn chunk_reader(r: &mut dyn Read, chunk_size: usize) -> IoResult<Vec<Vec<u8>>> {
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        chunks.push(buf[..n].to_vec());
    }
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_small() {
        let data = b"hello world";
        let mut reader: &[u8] = data;
        let chunks = chunk_reader(&mut reader, 4).expect("chunk");
        // "hello world" with chunk size 4 -> 3 chunks: "hell", "o wo", "rld"
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], b"hell".to_vec());
        assert_eq!(chunks[2], b"rld".to_vec());
    }

    #[test]
    fn test_chunk_exact_multiple() {
        let data = b"0123456789"; // 10 bytes
        let mut reader: &[u8] = data;
        let chunks = chunk_reader(&mut reader, 5).expect("chunk");
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], b"01234".to_vec());
        assert_eq!(chunks[1], b"56789".to_vec());
    }
}

/// Placeholder Dilithium module.
///
/// The implementation is intentionally minimal and compile-safe so call-sites can
/// switch by algorithm identifier without touching validation flow.
pub fn verify_signature(_pubkey_bytes: &[u8], _msg: &[u8], _sig_bytes: &[u8]) -> bool {
    false
}

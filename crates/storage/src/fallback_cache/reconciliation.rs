//! Reconciliation Hooks Module (14A.1A.56)
//!
//! Provides hook and state reconciliation tracking for FallbackCache.
//!
//! ## Features
//!
//! - Track pending sequences for reconciliation
//! - Track reconciled sequences
//! - Callback hooks for reconciliation events
//! - Thread-safe state management
//!
//! ## Invariants
//!
//! - A sequence CANNOT be in both pending and reconciled simultaneously
//! - reconciled ⊆ sequences that were previously pending
//! - Callbacks are invoked outside locks to prevent deadlock

use std::collections::HashSet;

// ════════════════════════════════════════════════════════════════════════════════
// RECONCILIATION CALLBACK TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Callback trait for reconciliation events.
///
/// ## Contract
///
/// - Implementations MUST NOT panic
/// - Implementations MUST NOT block
/// - error parameter is read-only (borrowed)
///
/// ## Thread Safety
///
/// Implementations must be Send + Sync for use across threads.
pub trait ReconciliationCallback: Send + Sync {
    /// Called when a sequence has been successfully reconciled.
    ///
    /// ## Guarantees
    ///
    /// - Called exactly once per sequence per reconciliation
    /// - Called after sequence moved from pending to reconciled
    fn on_reconcile_complete(&self, sequence: u64);

    /// Called when reconciliation of a sequence has failed.
    ///
    /// ## Arguments
    ///
    /// * `sequence` - The sequence number that failed
    /// * `error` - Description of the failure (read-only)
    fn on_reconcile_failed(&self, sequence: u64, error: &str);
}

// ════════════════════════════════════════════════════════════════════════════════
// RECONCILIATION STATE
// ════════════════════════════════════════════════════════════════════════════════

/// State tracking for reconciliation operations.
///
/// ## Invariants
///
/// - pending ∩ reconciled = ∅ (no sequence in both sets)
/// - reconciled only contains sequences that were previously pending
/// - callbacks can be empty
///
/// ## Thread Safety
///
/// This struct should be wrapped in RwLock for concurrent access.
pub struct ReconciliationState {
    /// Sequences pending reconciliation.
    pending: HashSet<u64>,
    /// Sequences that have been reconciled.
    reconciled: HashSet<u64>,
    /// Registered callbacks for reconciliation events.
    callbacks: Vec<Box<dyn ReconciliationCallback>>,
}

impl ReconciliationState {
    /// Create a new empty ReconciliationState.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: HashSet::new(),
            reconciled: HashSet::new(),
            callbacks: Vec::new(),
        }
    }

    /// Get the number of pending sequences.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Get the number of reconciled sequences.
    #[must_use]
    pub fn reconciled_count(&self) -> usize {
        self.reconciled.len()
    }

    /// Check if a sequence is pending.
    #[must_use]
    pub fn is_pending(&self, sequence: u64) -> bool {
        self.pending.contains(&sequence)
    }

    /// Check if a sequence is reconciled.
    #[must_use]
    pub fn is_reconciled(&self, sequence: u64) -> bool {
        self.reconciled.contains(&sequence)
    }

    /// Get a snapshot of all pending sequences.
    ///
    /// ## Returns
    ///
    /// Vector of sequence numbers currently pending.
    /// Order is not guaranteed.
    #[must_use]
    pub fn get_pending_sequences(&self) -> Vec<u64> {
        self.pending.iter().copied().collect()
    }

    /// Mark a sequence as pending for reconciliation.
    ///
    /// ## Behavior
    ///
    /// - If sequence is already pending → NO-OP
    /// - If sequence is in reconciled → removes from reconciled, adds to pending
    /// - Otherwise → adds to pending
    ///
    /// ## Returns
    ///
    /// true if sequence was added to pending, false if already pending
    pub fn mark_pending(&mut self, sequence: u64) -> bool {
        // Maintain invariant: remove from reconciled if present
        self.reconciled.remove(&sequence);

        // Add to pending
        self.pending.insert(sequence)
    }

    /// Mark a sequence as reconciled.
    ///
    /// ## Behavior
    ///
    /// - Removes sequence from pending
    /// - Adds sequence to reconciled
    /// - Returns list of callbacks to invoke (caller must invoke outside lock)
    ///
    /// ## Returns
    ///
    /// true if sequence was in pending and moved to reconciled
    ///
    /// ## Note
    ///
    /// Callbacks are NOT invoked by this method to avoid holding lock.
    /// Caller MUST invoke callbacks after releasing lock.
    pub fn mark_reconciled(&mut self, sequence: u64) -> bool {
        // Only process if sequence was pending
        if !self.pending.remove(&sequence) {
            return false;
        }

        // Add to reconciled
        self.reconciled.insert(sequence);
        true
    }

    /// Mark a sequence as failed reconciliation.
    ///
    /// ## Behavior
    ///
    /// - Removes sequence from pending (it can be retried later)
    /// - Does NOT add to reconciled
    ///
    /// ## Returns
    ///
    /// true if sequence was in pending
    pub fn mark_failed(&mut self, sequence: u64) -> bool {
        self.pending.remove(&sequence)
    }

    /// Clear all reconciled sequences.
    ///
    /// ## Returns
    ///
    /// Number of sequences cleared.
    pub fn clear_reconciled(&mut self) -> usize {
        let count = self.reconciled.len();
        self.reconciled.clear();
        count
    }

    /// Register a callback for reconciliation events.
    ///
    /// ## Guarantees
    ///
    /// - Does not panic
    /// - Callback will be invoked for future reconciliation events
    pub fn register_callback(&mut self, cb: Box<dyn ReconciliationCallback>) {
        self.callbacks.push(cb);
    }

    /// Get the number of registered callbacks.
    #[must_use]
    pub fn callback_count(&self) -> usize {
        self.callbacks.len()
    }

    /// Invoke on_reconcile_complete on all callbacks.
    ///
    /// ## Safety
    ///
    /// This method should be called OUTSIDE any lock to prevent deadlock.
    pub fn invoke_complete_callbacks(&self, sequence: u64) {
        for cb in &self.callbacks {
            cb.on_reconcile_complete(sequence);
        }
    }

    /// Invoke on_reconcile_failed on all callbacks.
    ///
    /// ## Safety
    ///
    /// This method should be called OUTSIDE any lock to prevent deadlock.
    pub fn invoke_failed_callbacks(&self, sequence: u64, error: &str) {
        for cb in &self.callbacks {
            cb.on_reconcile_failed(sequence, error);
        }
    }
}

impl Default for ReconciliationState {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ReconciliationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReconciliationState")
            .field("pending_count", &self.pending.len())
            .field("reconciled_count", &self.reconciled.len())
            .field("callback_count", &self.callbacks.len())
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    // Test callback implementation
    struct TestCallback {
        complete_count: AtomicU64,
        failed_count: AtomicU64,
        last_complete_seq: AtomicU64,
        last_failed_seq: AtomicU64,
    }

    impl TestCallback {
        fn new() -> Self {
            Self {
                complete_count: AtomicU64::new(0),
                failed_count: AtomicU64::new(0),
                last_complete_seq: AtomicU64::new(0),
                last_failed_seq: AtomicU64::new(0),
            }
        }
    }

    impl ReconciliationCallback for TestCallback {
        fn on_reconcile_complete(&self, sequence: u64) {
            self.complete_count.fetch_add(1, Ordering::SeqCst);
            self.last_complete_seq.store(sequence, Ordering::SeqCst);
        }

        fn on_reconcile_failed(&self, sequence: u64, _error: &str) {
            self.failed_count.fetch_add(1, Ordering::SeqCst);
            self.last_failed_seq.store(sequence, Ordering::SeqCst);
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // A. CONSTRUCTION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_reconciliation_state_new() {
        let state = ReconciliationState::new();

        assert_eq!(state.pending_count(), 0);
        assert_eq!(state.reconciled_count(), 0);
        assert_eq!(state.callback_count(), 0);
    }

    #[test]
    fn test_reconciliation_state_default() {
        let state = ReconciliationState::default();

        assert_eq!(state.pending_count(), 0);
        assert_eq!(state.reconciled_count(), 0);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // B. MARK PENDING TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_mark_pending_adds_sequence() {
        let mut state = ReconciliationState::new();

        let added = state.mark_pending(1);

        assert!(added);
        assert_eq!(state.pending_count(), 1);
        assert!(state.is_pending(1));
    }

    #[test]
    fn test_mark_pending_duplicate_noop() {
        let mut state = ReconciliationState::new();

        state.mark_pending(1);
        let added = state.mark_pending(1);

        assert!(!added); // Already pending
        assert_eq!(state.pending_count(), 1);
    }

    #[test]
    fn test_mark_pending_multiple_sequences() {
        let mut state = ReconciliationState::new();

        state.mark_pending(1);
        state.mark_pending(2);
        state.mark_pending(3);

        assert_eq!(state.pending_count(), 3);
        assert!(state.is_pending(1));
        assert!(state.is_pending(2));
        assert!(state.is_pending(3));
    }

    #[test]
    fn test_mark_pending_removes_from_reconciled() {
        let mut state = ReconciliationState::new();

        // First reconcile sequence 1
        state.mark_pending(1);
        state.mark_reconciled(1);
        assert!(state.is_reconciled(1));
        assert!(!state.is_pending(1));

        // Now mark it pending again
        state.mark_pending(1);

        // Should be pending, not reconciled (invariant maintained)
        assert!(state.is_pending(1));
        assert!(!state.is_reconciled(1));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // C. MARK RECONCILED TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_mark_reconciled_moves_from_pending() {
        let mut state = ReconciliationState::new();

        state.mark_pending(1);
        assert!(state.is_pending(1));

        let moved = state.mark_reconciled(1);

        assert!(moved);
        assert!(!state.is_pending(1));
        assert!(state.is_reconciled(1));
        assert_eq!(state.pending_count(), 0);
        assert_eq!(state.reconciled_count(), 1);
    }

    #[test]
    fn test_mark_reconciled_not_pending_noop() {
        let mut state = ReconciliationState::new();

        let moved = state.mark_reconciled(999);

        assert!(!moved);
        assert_eq!(state.reconciled_count(), 0);
    }

    #[test]
    fn test_mark_reconciled_multiple() {
        let mut state = ReconciliationState::new();

        state.mark_pending(1);
        state.mark_pending(2);
        state.mark_pending(3);

        state.mark_reconciled(1);
        state.mark_reconciled(3);

        assert_eq!(state.pending_count(), 1);
        assert_eq!(state.reconciled_count(), 2);
        assert!(state.is_pending(2));
        assert!(state.is_reconciled(1));
        assert!(state.is_reconciled(3));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // D. MARK FAILED TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_mark_failed_removes_from_pending() {
        let mut state = ReconciliationState::new();

        state.mark_pending(1);
        let removed = state.mark_failed(1);

        assert!(removed);
        assert!(!state.is_pending(1));
        assert!(!state.is_reconciled(1));
    }

    #[test]
    fn test_mark_failed_not_pending_noop() {
        let mut state = ReconciliationState::new();

        let removed = state.mark_failed(999);

        assert!(!removed);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // E. CLEAR RECONCILED TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_clear_reconciled_returns_count() {
        let mut state = ReconciliationState::new();

        state.mark_pending(1);
        state.mark_pending(2);
        state.mark_pending(3);
        state.mark_reconciled(1);
        state.mark_reconciled(2);
        state.mark_reconciled(3);

        let cleared = state.clear_reconciled();

        assert_eq!(cleared, 3);
        assert_eq!(state.reconciled_count(), 0);
    }

    #[test]
    fn test_clear_reconciled_empty() {
        let mut state = ReconciliationState::new();

        let cleared = state.clear_reconciled();

        assert_eq!(cleared, 0);
    }

    #[test]
    fn test_clear_reconciled_does_not_affect_pending() {
        let mut state = ReconciliationState::new();

        state.mark_pending(1);
        state.mark_pending(2);
        state.mark_reconciled(1);

        state.clear_reconciled();

        assert_eq!(state.pending_count(), 1);
        assert!(state.is_pending(2));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // F. GET PENDING SEQUENCES TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_get_pending_sequences_returns_all() {
        let mut state = ReconciliationState::new();

        state.mark_pending(1);
        state.mark_pending(5);
        state.mark_pending(10);

        let sequences = state.get_pending_sequences();

        assert_eq!(sequences.len(), 3);
        assert!(sequences.contains(&1));
        assert!(sequences.contains(&5));
        assert!(sequences.contains(&10));
    }

    #[test]
    fn test_get_pending_sequences_empty() {
        let state = ReconciliationState::new();

        let sequences = state.get_pending_sequences();

        assert!(sequences.is_empty());
    }

    #[test]
    fn test_get_pending_sequences_does_not_modify_state() {
        let mut state = ReconciliationState::new();
        state.mark_pending(1);
        state.mark_pending(2);

        let _ = state.get_pending_sequences();
        let _ = state.get_pending_sequences();

        assert_eq!(state.pending_count(), 2);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // G. CALLBACK REGISTRATION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_register_callback() {
        let mut state = ReconciliationState::new();
        let cb = Box::new(TestCallback::new());

        state.register_callback(cb);

        assert_eq!(state.callback_count(), 1);
    }

    #[test]
    fn test_register_multiple_callbacks() {
        let mut state = ReconciliationState::new();

        state.register_callback(Box::new(TestCallback::new()));
        state.register_callback(Box::new(TestCallback::new()));
        state.register_callback(Box::new(TestCallback::new()));

        assert_eq!(state.callback_count(), 3);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // H. CALLBACK INVOCATION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_invoke_complete_callbacks() {
        let mut state = ReconciliationState::new();
        let cb = Arc::new(TestCallback::new());

        // We need to use Arc for shared access in test
        struct ArcCallback(Arc<TestCallback>);
        impl ReconciliationCallback for ArcCallback {
            fn on_reconcile_complete(&self, sequence: u64) {
                self.0.on_reconcile_complete(sequence);
            }
            fn on_reconcile_failed(&self, sequence: u64, error: &str) {
                self.0.on_reconcile_failed(sequence, error);
            }
        }

        state.register_callback(Box::new(ArcCallback(Arc::clone(&cb))));

        state.invoke_complete_callbacks(42);

        assert_eq!(cb.complete_count.load(Ordering::SeqCst), 1);
        assert_eq!(cb.last_complete_seq.load(Ordering::SeqCst), 42);
    }

    #[test]
    fn test_invoke_failed_callbacks() {
        let mut state = ReconciliationState::new();
        let cb = Arc::new(TestCallback::new());

        struct ArcCallback(Arc<TestCallback>);
        impl ReconciliationCallback for ArcCallback {
            fn on_reconcile_complete(&self, sequence: u64) {
                self.0.on_reconcile_complete(sequence);
            }
            fn on_reconcile_failed(&self, sequence: u64, error: &str) {
                self.0.on_reconcile_failed(sequence, error);
            }
        }

        state.register_callback(Box::new(ArcCallback(Arc::clone(&cb))));

        state.invoke_failed_callbacks(99, "test error");

        assert_eq!(cb.failed_count.load(Ordering::SeqCst), 1);
        assert_eq!(cb.last_failed_seq.load(Ordering::SeqCst), 99);
    }

    #[test]
    fn test_invoke_callbacks_multiple_registered() {
        let mut state = ReconciliationState::new();
        let cb1 = Arc::new(TestCallback::new());
        let cb2 = Arc::new(TestCallback::new());

        struct ArcCallback(Arc<TestCallback>);
        impl ReconciliationCallback for ArcCallback {
            fn on_reconcile_complete(&self, sequence: u64) {
                self.0.on_reconcile_complete(sequence);
            }
            fn on_reconcile_failed(&self, sequence: u64, error: &str) {
                self.0.on_reconcile_failed(sequence, error);
            }
        }

        state.register_callback(Box::new(ArcCallback(Arc::clone(&cb1))));
        state.register_callback(Box::new(ArcCallback(Arc::clone(&cb2))));

        state.invoke_complete_callbacks(100);

        // Both callbacks should be invoked
        assert_eq!(cb1.complete_count.load(Ordering::SeqCst), 1);
        assert_eq!(cb2.complete_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_callback_invoked_once_per_call() {
        let mut state = ReconciliationState::new();
        let cb = Arc::new(TestCallback::new());

        struct ArcCallback(Arc<TestCallback>);
        impl ReconciliationCallback for ArcCallback {
            fn on_reconcile_complete(&self, sequence: u64) {
                self.0.on_reconcile_complete(sequence);
            }
            fn on_reconcile_failed(&self, sequence: u64, error: &str) {
                self.0.on_reconcile_failed(sequence, error);
            }
        }

        state.register_callback(Box::new(ArcCallback(Arc::clone(&cb))));

        // Multiple invocations
        state.invoke_complete_callbacks(1);
        state.invoke_complete_callbacks(2);
        state.invoke_complete_callbacks(3);

        assert_eq!(cb.complete_count.load(Ordering::SeqCst), 3);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // I. STATE INVARIANT TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_invariant_no_sequence_in_both_sets() {
        let mut state = ReconciliationState::new();

        // Add to pending
        state.mark_pending(1);
        assert!(state.is_pending(1));
        assert!(!state.is_reconciled(1));

        // Move to reconciled
        state.mark_reconciled(1);
        assert!(!state.is_pending(1));
        assert!(state.is_reconciled(1));

        // Mark pending again
        state.mark_pending(1);
        assert!(state.is_pending(1));
        assert!(!state.is_reconciled(1));
    }

    #[test]
    fn test_invariant_reconciled_only_from_pending() {
        let mut state = ReconciliationState::new();

        // Try to reconcile without pending first
        let moved = state.mark_reconciled(1);

        assert!(!moved);
        assert!(!state.is_reconciled(1));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // J. THREAD SAFETY TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_reconciliation_state_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ReconciliationState>();
    }

    // ReconciliationState is NOT Sync because it contains Vec<Box<dyn ReconciliationCallback>>
    // but that's OK because it's wrapped in RwLock in FallbackCache

    #[test]
    fn test_reconciliation_callback_trait_bounds() {
        fn assert_bounds<T: ReconciliationCallback + Send + Sync>() {}
        assert_bounds::<TestCallback>();
    }
}
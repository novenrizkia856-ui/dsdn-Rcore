use std::sync::Arc;
use crate::coord_client::CoordinatorClient;
use crate::economic_handlers;

// ════════════════════════════════════════════════════════════════════════════
// RECEIPT QUERY STUB (14C.C.24)
// ════════════════════════════════════════════════════════════════════════════

/// Stub implementation of [`economic_handlers::ReceiptQueryService`] backed
/// by `CoordinatorClient`.
///
/// Returns `not_found` for all queries until coordinator RPC exposes a real
/// receipt-status endpoint.  HTTP routes, validation, and batch logic are
/// fully functional regardless.
#[derive(Clone)]
#[allow(dead_code)]
pub struct CoordinatorReceiptQueryStub {
    _coord: Arc<CoordinatorClient>,
}

impl CoordinatorReceiptQueryStub {
    pub fn new(coord: Arc<CoordinatorClient>) -> Self {
        Self { _coord: coord }
    }
}

impl economic_handlers::ReceiptQueryService for CoordinatorReceiptQueryStub {
    fn query_receipt(
        &self,
        _receipt_hash: &str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<economic_handlers::ChainReceiptInfo, String>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            // NOTE(14C.C.24): Replace with real coordinator RPC call.
            //   e.g. self._coord.query_receipt_status(receipt_hash).await
            Ok(economic_handlers::ChainReceiptInfo {
                status: economic_handlers::ReceiptStatus::NotFound,
                reward_amount: None,
                challenge_expires_at: None,
                node_id: None,
                workload_type: None,
                submitted_at: None,
            })
        })
    }
}

/// Stub implementation of [`economic_handlers::RewardQueryService`] backed
/// by `CoordinatorClient`.
///
/// Returns zero-balance / empty results for all queries until coordinator RPC
/// exposes real reward-state endpoints.  HTTP routes, validation, and sorting
/// logic are fully functional regardless.
#[derive(Clone)]
#[allow(dead_code)]
pub struct CoordinatorRewardQueryStub {
    _coord: Arc<CoordinatorClient>,
}

impl CoordinatorRewardQueryStub {
    pub fn new(coord: Arc<CoordinatorClient>) -> Self {
        Self { _coord: coord }
    }
}

impl economic_handlers::RewardQueryService for CoordinatorRewardQueryStub {
    fn query_balance(
        &self,
        _address: &str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<economic_handlers::ChainRewardInfo, String>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            // NOTE(14C.C.25): Replace with real coordinator RPC call.
            Ok(economic_handlers::ChainRewardInfo {
                balance: 0,
                pending_rewards: 0,
                claimed_rewards: 0,
                node_earnings: 0,
                is_validator: false,
                is_node: false,
            })
        })
    }

    fn list_validator_rewards(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Vec<economic_handlers::ChainValidatorRewardInfo>, String>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            // NOTE(14C.C.25): Replace with real coordinator RPC call.
            Ok(Vec::new())
        })
    }

    fn query_treasury(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<economic_handlers::ChainTreasuryInfo, String>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            // NOTE(14C.C.25): Replace with real coordinator RPC call.
            Ok(economic_handlers::ChainTreasuryInfo {
                treasury_balance: 0,
                total_rewards_distributed: 0,
                total_validator_rewards: 0,
                total_node_rewards: 0,
            })
        })
    }
}
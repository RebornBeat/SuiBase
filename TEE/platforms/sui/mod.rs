//! Sui blockchain integration for SuiStack0X TEE Framework

pub mod attestation;
pub mod blockchain_interface;
pub mod command_processor;
pub mod compute_integration;
pub mod edge_integration;
pub mod index_integration;
pub mod move_execution;
pub mod transaction;

// Re-exports for convenient usage
pub use attestation::{SuiAttestationManager, SuiAttestationProof};
pub use blockchain_interface::{BlockchainCredentials, SuiClient, TEEBlockchainInterface};
pub use command_processor::{BlockchainCommand, CommandProcessor};
pub use compute_integration::ComputeTEEIntegration;
pub use edge_integration::EdgeTEEIntegration;
pub use index_integration::IndexTEEIntegration;
pub use move_execution::{MoveExecutionEnvironment, MoveExecutionResult};
pub use transaction::{ExecuteContractParams, TransactionBuilder, TransactionResult};

// Constants for blockchain integration
pub const TEE_REGISTRY_MODULE: &str = "suistack0x::tee::registry";
pub const TEE_EXECUTION_MODULE: &str = "suistack0x::tee::execution";
pub const TEE_VERIFICATION_MODULE: &str = "suistack0x::tee::verification";

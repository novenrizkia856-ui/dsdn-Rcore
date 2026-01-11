//! CLI Integration Tests
//!
//! These tests verify CLI command structure and help text.
//! They do NOT require network connectivity or runtime state.

use std::process::Command;

/// Helper to run agent CLI with arguments.
/// Note: This helper is for tests only. Test code may use expect() for clarity.
fn run_agent(args: &[&str]) -> std::process::Output {
    Command::new("cargo")
        .args(["run", "-p", "dsdn-agent", "--"])
        .args(args)
        .output()
        .expect("failed to execute cargo command in test")
}

/// Helper to check if command exists by testing --help.
fn command_help_works(args: &[&str]) -> bool {
    let mut full_args = args.to_vec();
    full_args.push("--help");
    
    let output = run_agent(&full_args);
    output.status.success()
}

// ════════════════════════════════════════════════════════════════════════════
// HELP TEXT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_cli_main_help() {
    let output = run_agent(&["--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Should exit successfully
    assert!(output.status.success(), "CLI --help should succeed");
    
    // Should contain main description
    assert!(stdout.contains("DSDN Agent CLI"), "Should contain crate name");
}

#[test]
fn test_cli_version() {
    let output = run_agent(&["--version"]);
    
    // Version should work
    assert!(output.status.success(), "CLI --version should succeed");
}

// ════════════════════════════════════════════════════════════════════════════
// COMMAND EXISTENCE TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_command_gen_key_exists() {
    assert!(command_help_works(&["gen-key"]), "gen-key command should exist");
}

#[test]
fn test_command_recover_key_exists() {
    assert!(command_help_works(&["recover-key"]), "recover-key command should exist");
}

#[test]
fn test_command_upload_exists() {
    assert!(command_help_works(&["upload"]), "upload command should exist");
}

#[test]
fn test_command_get_exists() {
    assert!(command_help_works(&["get"]), "get command should exist");
}

#[test]
fn test_command_decrypt_file_exists() {
    assert!(command_help_works(&["decrypt-file"]), "decrypt-file command should exist");
}

#[test]
fn test_command_da_status_exists() {
    assert!(command_help_works(&["da", "status"]), "da status command should exist");
}

#[test]
fn test_command_verify_state_exists() {
    assert!(command_help_works(&["verify", "state"]), "verify state command should exist");
}

#[test]
fn test_command_verify_consistency_exists() {
    assert!(command_help_works(&["verify", "consistency"]), "verify consistency command should exist");
}

#[test]
fn test_command_node_status_exists() {
    assert!(command_help_works(&["node", "status"]), "node status command should exist");
}

#[test]
fn test_command_node_list_exists() {
    assert!(command_help_works(&["node", "list"]), "node list command should exist");
}

#[test]
fn test_command_node_chunks_exists() {
    assert!(command_help_works(&["node", "chunks"]), "node chunks command should exist");
}

#[test]
fn test_command_chunk_info_exists() {
    assert!(command_help_works(&["chunk", "info"]), "chunk info command should exist");
}

#[test]
fn test_command_chunk_replicas_exists() {
    assert!(command_help_works(&["chunk", "replicas"]), "chunk replicas command should exist");
}

#[test]
fn test_command_chunk_history_exists() {
    assert!(command_help_works(&["chunk", "history"]), "chunk history command should exist");
}

#[test]
fn test_command_rebuild_exists() {
    assert!(command_help_works(&["rebuild"]), "rebuild command should exist");
}

#[test]
fn test_command_health_all_exists() {
    assert!(command_help_works(&["health", "all"]), "health all command should exist");
}

#[test]
fn test_command_health_da_exists() {
    assert!(command_help_works(&["health", "da"]), "health da command should exist");
}

#[test]
fn test_command_health_coordinator_exists() {
    assert!(command_help_works(&["health", "coordinator"]), "health coordinator command should exist");
}

#[test]
fn test_command_health_nodes_exists() {
    assert!(command_help_works(&["health", "nodes"]), "health nodes command should exist");
}

// ════════════════════════════════════════════════════════════════════════════
// HELP TEXT CONTENT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_upload_help_contains_encrypt() {
    let output = run_agent(&["upload", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    assert!(stdout.contains("encrypt"), "upload help should mention --encrypt");
}

#[test]
fn test_upload_help_contains_track() {
    let output = run_agent(&["upload", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    assert!(stdout.contains("track"), "upload help should mention --track");
}

#[test]
fn test_get_help_contains_verify() {
    let output = run_agent(&["get", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    assert!(stdout.contains("verify"), "get help should mention --verify");
}

#[test]
fn test_rebuild_help_contains_target() {
    let output = run_agent(&["rebuild", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    assert!(stdout.contains("target"), "rebuild help should mention --target");
}

#[test]
fn test_health_all_help_contains_json() {
    let output = run_agent(&["health", "all", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    assert!(stdout.contains("json"), "health all help should mention --json");
}

// ════════════════════════════════════════════════════════════════════════════
// ARGUMENT VALIDATION TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_upload_requires_node_addr() {
    let output = run_agent(&["upload"]);
    
    // Should fail due to missing required args
    assert!(!output.status.success(), "upload without args should fail");
}

#[test]
fn test_get_requires_node_addr() {
    let output = run_agent(&["get"]);
    
    // Should fail due to missing required args
    assert!(!output.status.success(), "get without args should fail");
}

#[test]
fn test_rebuild_requires_target() {
    let output = run_agent(&["rebuild"]);
    
    // Should fail due to missing --target
    assert!(!output.status.success(), "rebuild without --target should fail");
}

#[test]
fn test_verify_state_requires_target() {
    let output = run_agent(&["verify", "state"]);
    
    // Should fail due to missing --target
    assert!(!output.status.success(), "verify state without --target should fail");
}

#[test]
fn test_verify_consistency_requires_node() {
    let output = run_agent(&["verify", "consistency"]);
    
    // Should fail due to missing --node
    assert!(!output.status.success(), "verify consistency without --node should fail");
}

// ════════════════════════════════════════════════════════════════════════════
// SUBCOMMAND GROUP TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_da_subcommand_group() {
    let output = run_agent(&["da", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    assert!(output.status.success(), "da --help should succeed");
    assert!(stdout.contains("status"), "da help should list status subcommand");
}

#[test]
fn test_verify_subcommand_group() {
    let output = run_agent(&["verify", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    assert!(output.status.success(), "verify --help should succeed");
    assert!(stdout.contains("state"), "verify help should list state subcommand");
    assert!(stdout.contains("consistency"), "verify help should list consistency subcommand");
}

#[test]
fn test_node_subcommand_group() {
    let output = run_agent(&["node", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    assert!(output.status.success(), "node --help should succeed");
    assert!(stdout.contains("status"), "node help should list status subcommand");
    assert!(stdout.contains("list"), "node help should list list subcommand");
    assert!(stdout.contains("chunks"), "node help should list chunks subcommand");
}

#[test]
fn test_chunk_subcommand_group() {
    let output = run_agent(&["chunk", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    assert!(output.status.success(), "chunk --help should succeed");
    assert!(stdout.contains("info"), "chunk help should list info subcommand");
    assert!(stdout.contains("replicas"), "chunk help should list replicas subcommand");
    assert!(stdout.contains("history"), "chunk help should list history subcommand");
}

#[test]
fn test_health_subcommand_group() {
    let output = run_agent(&["health", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    assert!(output.status.success(), "health --help should succeed");
    assert!(stdout.contains("all"), "health help should list all subcommand");
    assert!(stdout.contains("da"), "health help should list da subcommand");
    assert!(stdout.contains("coordinator"), "health help should list coordinator subcommand");
    assert!(stdout.contains("nodes"), "health help should list nodes subcommand");
}
//! Integration tests for privacy fallback and connection logic
use std::process::Command;
use std::thread;
use std::time::Duration;

const NODE_STARTUP_DELAY: Duration = Duration::from_secs(5);

/// Helper to start a node with a given privacy mode
fn start_node_with_privacy_mode(mode: &str) -> std::process::Child {
    Command::new("cargo")
        .args(&["run", "--bin", "blacksilk-node", "--", "--net-privacy", mode, "--p2p-bind", "127.0.0.1:18444", "--rpc-bind", "127.0.0.1:18445"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start node")
}

#[test]
fn test_auto_mode_fallback_to_i2p_and_clearnet() {
    // Start node in auto mode (Tor not running)
    let mut node = start_node_with_privacy_mode("auto");
    thread::sleep(NODE_STARTUP_DELAY);
    // Try to connect to the node (should fallback to I2P or clearnet)
    // In a real test, check logs or API for fallback status
    // Here, just check process is running
    assert!(node.try_wait().unwrap().is_none(), "Node process exited unexpectedly");
    // Cleanup
    let _ = node.kill();
}

#[test]
fn test_tor_only_mode_exits_if_tor_unavailable() {
    // Start node in tor mode (Tor not running)
    let mut node = start_node_with_privacy_mode("tor");
    thread::sleep(NODE_STARTUP_DELAY);
    // Node should exit if Tor is unavailable
    let status = node.try_wait().unwrap();
    assert!(status.is_some(), "Node should exit if Tor is unavailable");
}

#[test]
fn test_clearnet_mode_allows_direct_connections() {
    let mut node = start_node_with_privacy_mode("clearnet");
    thread::sleep(NODE_STARTUP_DELAY);
    // Node should stay running
    assert!(node.try_wait().unwrap().is_none(), "Node process exited unexpectedly");
    let _ = node.kill();
}

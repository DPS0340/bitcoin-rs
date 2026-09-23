//! ARCH-01..ARCH-04: check the live Cargo graph against the architecture contract.

#[path = "../support/dependency_graph.rs"]
mod dependency_graph;

use dependency_graph::WorkspaceGraph;

#[test]
fn workspace_dependency_direction_is_one_way() {
    let graph = WorkspaceGraph::from_cargo_metadata();
    assert!(
        graph.classified >= 12,
        "workspace crates went missing from metadata: {} classified",
        graph.classified
    );
    match graph.validate() {
        Ok(report) => {
            assert!(
                report.checked_edges > 0 && report.checked_features > 0,
                "validator checked nothing: {}",
                report.summary
            );
            assert!(
                report.cycle_checked_crates >= 12,
                "cycle check did not run: {}",
                report.summary
            );
        }
        Err(violations) => {
            panic!(
                "dependency direction violations:\n{}",
                violations.join("\n")
            );
        }
    }
}

#[test]
fn chainstate_facade_exposes_no_production_raw_mutation_handles()
-> Result<(), Box<dyn std::error::Error>> {
    let root = dependency_graph::workspace_root_manifest()
        .parent()
        .ok_or_else(|| std::io::Error::other("workspace root"))?
        .to_path_buf();
    let chainstate = std::fs::read_to_string(root.join("crates/chainstate/src/lib.rs"))?;
    let test_gate = "#[cfg(any(test, feature = \"test-seam\"))]";
    for method in [
        "chain_tip",
        "chain_tip_handle",
        "applied_tip",
        "applied_tip_handle",
        "block_tree",
        "block_tree_handle",
        "transition_barrier",
        "apply_block",
        "apply_block_with_serialized",
        "disconnect_block",
        "apply_window",
    ] {
        let signature = format!("pub fn {method}(");
        let position = chainstate
            .find(&signature)
            .unwrap_or_else(|| panic!("expected fixture method `{signature}`"));
        let prefix = &chainstate[..position];
        let gate = prefix
            .rfind(test_gate)
            .unwrap_or_else(|| panic!("`{signature}` is not test-gated"));
        let previous_public_method = prefix.rfind("pub fn ").unwrap_or(0);
        assert!(
            gate > previous_public_method,
            "`{signature}` escaped its test-only capability gate"
        );
    }

    let node_sync = std::fs::read_to_string(root.join("crates/node/src/sync.rs"))?;
    assert!(node_sync.contains("self.handles.admit_headers(headers)"));
    assert!(node_sync.contains("self.handles.finish_genesis_bootstrap(&outcome.tip)"));
    assert!(!node_sync.contains("block_tree().write()"));
    assert!(!node_sync.contains("chain_tip().store("));

    let p2p_chain = std::fs::read_to_string(root.join("crates/p2p/src/sync/chain.rs"))?;
    let trait_body = p2p_chain
        .split_once("pub trait SyncChain")
        .ok_or_else(|| std::io::Error::other("SyncChain trait"))?
        .1;
    assert!(!trait_body.contains("ArcSwapOption"));
    assert!(!trait_body.contains("&RwLock<BlockTree>"));
    Ok(())
}

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

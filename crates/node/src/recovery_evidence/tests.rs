use super::*;

#[cfg(test)]
mod validation_1;

#[cfg(test)]
mod persistence_1;

#[cfg(test)]
mod behavior_1;

/// Reads back the most recent valid marker event. The runtime never reads
/// the marker (it is write-only audit evidence at runtime); these tests pin
/// the write protocol, so the oracle lives here instead of production.
fn read_marker(dir: &std::path::Path, genesis_hash: &str) -> Option<ChainRollbackEvent> {
    let data = io::read_bounded(dir, MARKER_FILE, MARKER_PREV)?;
    let event = ChainRollbackEvent::from_json(&data)?;
    if !event.is_valid_for(MARKER_FORMAT, genesis_hash) {
        return None;
    }
    Some(event)
}

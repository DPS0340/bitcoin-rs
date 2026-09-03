use bitcoin_rs_script::is_p2tr;

use crate::ConsensusError;

/// Checks that a script pubkey is a valid BIP341 taproot output.
pub fn check_bip341(script_pubkey: &[u8]) -> Result<(), ConsensusError> {
    if is_p2tr(script_pubkey) {
        return Ok(());
    }
    Err(ConsensusError::Bip {
        bip: "BIP341",
        reason: "script pubkey is not a v1 32-byte taproot witness program".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::check_bip341;

    #[test]
    fn p2tr_output_passes() {
        let script = [vec![0x51, 0x20], vec![3; 32]].concat();
        assert_eq!(check_bip341(&script), Ok(()));
    }

    #[test]
    fn non_taproot_output_fails() {
        let script = [vec![0x00, 0x14], vec![3; 20]].concat();
        assert!(check_bip341(&script).is_err());
    }
}

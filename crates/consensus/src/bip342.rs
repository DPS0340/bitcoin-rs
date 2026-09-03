use crate::{ConsensusError, MAX_SCRIPT_SIZE};

/// Checks BIP342 tapscript size and non-empty script invariants.
pub fn check_bip342(tapscript: &[u8]) -> Result<(), ConsensusError> {
    if tapscript.is_empty() {
        return Err(ConsensusError::Bip {
            bip: "BIP342",
            reason: "empty tapscript".to_owned(),
        });
    }
    if tapscript.len() > MAX_SCRIPT_SIZE {
        return Err(ConsensusError::Bip {
            bip: "BIP342",
            reason: format!(
                "tapscript size {} exceeds {MAX_SCRIPT_SIZE}",
                tapscript.len()
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_bip342;

    #[test]
    fn non_empty_tapscript_passes() {
        assert_eq!(check_bip342(&[0x51]), Ok(()));
    }

    #[test]
    fn empty_tapscript_fails() {
        assert!(check_bip342(&[]).is_err());
    }
}

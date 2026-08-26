//! Script-template classification used by the local consensus evaluator.
//!
//! The shape follows `reardencode/rbitcoin` at commit
//! `b6ad818e4aa36e5b4a9f8a0d83feb8f3b036937` (MIT OR Apache-2.0). This is a
//! local implementation; the repository does not depend on `rbitcoin`.

use bitcoin::Script;

use crate::{p2pkh, p2wpkh, p2wsh};

/// Recognized consensus script families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScriptClass {
    /// A script that is not a recognized standard template.
    Bare,
    /// A pay-to-public-key template.
    P2pk,
    /// A pay-to-public-key-hash template.
    P2pkh,
    /// A pay-to-script-hash template.
    P2sh,
    /// A native or nested version-0 key-hash witness program.
    WitnessV0P2wpkh,
    /// A native or nested version-0 script-hash witness program.
    WitnessV0P2wsh,
    /// A version-1, 32-byte taproot output.
    Taproot,
    /// A witness program whose version or length is not yet interpreted here.
    UnknownWitness,
}

/// Classifies one scriptPubKey without allocating or decoding its pushes.
#[must_use]
pub(crate) fn classify(script: &Script) -> ScriptClass {
    if p2pkh::pubkey_hash(script).is_some() {
        return ScriptClass::P2pkh;
    }
    if script.is_p2sh() {
        return ScriptClass::P2sh;
    }
    if script.is_p2tr() {
        return ScriptClass::Taproot;
    }
    if p2wpkh::program(script).is_some() {
        return ScriptClass::WitnessV0P2wpkh;
    }
    if p2wsh::program(script).is_some() {
        return ScriptClass::WitnessV0P2wsh;
    }
    if let Some((version, program)) = witness_program(script) {
        return match (version, program.len()) {
            (1, 32) => ScriptClass::Taproot,
            _ => ScriptClass::UnknownWitness,
        };
    }
    if is_p2pk(script) {
        ScriptClass::P2pk
    } else {
        ScriptClass::Bare
    }
}

/// Extracts a minimally shaped witness version/program pair.
#[must_use]
pub(crate) fn witness_program(script: &Script) -> Option<(u8, &[u8])> {
    let bytes = script.as_bytes();
    if !(4..=42).contains(&bytes.len()) {
        return None;
    }
    let (&version_opcode, rest) = bytes.split_first()?;
    let version = match version_opcode {
        0x00 => 0,
        0x51..=0x60 => version_opcode - 0x50,
        _ => return None,
    };
    let (&length, program) = rest.split_first()?;
    let length = usize::from(length);
    if !(2..=40).contains(&length) || program.len() != length {
        return None;
    }
    Some((version, program))
}

fn is_p2pk(script: &Script) -> bool {
    let bytes = script.as_bytes();
    matches!(bytes.last(), Some(0xac))
        && matches!(bytes.first(), Some(33) | Some(65))
        && bytes.len() == usize::from(bytes[0]) + 2
}
#[cfg(test)]
mod tests {
    use bitcoin::ScriptBuf;

    use super::{ScriptClass, classify};
    use crate::{p2pkh, p2wpkh, p2wsh};

    #[test]
    fn canonical_templates_and_malformed_witnesses_have_stable_classes() {
        let p2pk = {
            let mut bytes = vec![33, 0x02];
            bytes.extend_from_slice(&[7; 32]);
            bytes.push(0xac);
            ScriptBuf::from_bytes(bytes)
        };
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend_from_slice(&[1; 20]);
        p2pkh.extend_from_slice(&[0x88, 0xac]);
        let mut p2sh = vec![0xa9, 0x14];
        p2sh.extend_from_slice(&[2; 20]);
        p2sh.push(0x87);
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(&[3; 20]);
        let mut p2wsh = vec![0x00, 0x20];
        p2wsh.extend_from_slice(&[4; 32]);
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&[5; 32]);

        assert_eq!(
            p2pkh::pubkey_hash(ScriptBuf::from_bytes(p2pkh.clone()).as_script()),
            Some([1; 20])
        );
        assert_eq!(
            p2wpkh::program(ScriptBuf::from_bytes(p2wpkh.clone()).as_script()),
            Some([3; 20])
        );
        assert_eq!(
            p2wsh::program(ScriptBuf::from_bytes(p2wsh.clone()).as_script()),
            Some([4; 32])
        );
        assert_eq!(
            super::witness_program(ScriptBuf::from_bytes(p2tr.clone()).as_script()),
            Some((1, &[5; 32][..]))
        );
        assert_eq!(
            p2wsh::program(ScriptBuf::from_bytes(vec![0x00, 0x20]).as_script()),
            None
        );

        let cases = [
            (p2pk, ScriptClass::P2pk),
            (ScriptBuf::from_bytes(p2pkh), ScriptClass::P2pkh),
            (ScriptBuf::from_bytes(p2sh), ScriptClass::P2sh),
            (ScriptBuf::from_bytes(p2wpkh), ScriptClass::WitnessV0P2wpkh),
            (ScriptBuf::from_bytes(p2wsh), ScriptClass::WitnessV0P2wsh),
            (ScriptBuf::from_bytes(p2tr), ScriptClass::Taproot),
            (
                ScriptBuf::from_bytes(vec![0x51, 0x02, 1, 2]),
                ScriptClass::UnknownWitness,
            ),
            (
                ScriptBuf::from_bytes(vec![0x51, 0x01, 0]),
                ScriptClass::Bare,
            ),
        ];
        for (script, expected) in cases {
            assert_eq!(classify(script.as_script()), expected);
        }
    }
}

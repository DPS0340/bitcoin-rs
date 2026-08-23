use core::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bitcoin::{Address, Network, PublicKey};
use miniscript::Descriptor as MiniscriptDescriptor;
use miniscript::descriptor::{DescriptorPublicKey, DescriptorType};
use serde::{Deserialize, Serialize};

use crate::WalletError;

/// Public BIP32 origin metadata attached to descriptor keys.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BIP32Derivation {
    /// Master key fingerprint for the origin key, when known.
    pub fingerprint: Option<Fingerprint>,
    /// Non-hardened public derivation path, when known.
    pub path: DerivationPath,
}

impl BIP32Derivation {
    /// Returns a copy with `index` appended as a normal child number.
    pub fn with_child(&self, index: u32) -> Result<Self, WalletError> {
        let child = ChildNumber::from_normal_idx(index)
            .map_err(|error| WalletError::Descriptor(error.to_string()))?;
        let mut children: Vec<ChildNumber> = self.path.into_iter().copied().collect();
        children.push(child);
        Ok(Self {
            fingerprint: self.fingerprint,
            path: DerivationPath::from(children),
        })
    }
}

/// Public, watch-only output descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Descriptor {
    /// Parsed miniscript descriptor with public keys only.
    pub inner: MiniscriptDescriptor<PublicKey>,
    /// Public BIP32 derivation metadata.
    pub derivation: BIP32Derivation,
}

impl Descriptor {
    /// Parses one supported public descriptor form.
    pub fn parse(text: &str) -> Result<Self, WalletError> {
        let inner = MiniscriptDescriptor::<PublicKey>::from_str(text)
            .map_err(|error| WalletError::Descriptor(error.to_string()))?;
        ensure_supported(&inner)?;
        Ok(Self {
            inner,
            derivation: BIP32Derivation::default(),
        })
    }

    /// Derives the receive address for a descriptor index.
    pub fn derive_address(&self, network: Network, index: u32) -> Result<Address, WalletError> {
        let _derivation = self.derivation.with_child(index)?;
        self.inner
            .address(network)
            .map_err(|error| WalletError::Descriptor(error.to_string()))
    }

    /// Returns the descriptor script pubkey.
    #[must_use]
    pub fn script_pubkey(&self) -> bitcoin::ScriptBuf {
        self.inner.script_pubkey()
    }
}

impl FromStr for Descriptor {
    type Err = WalletError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

fn ensure_supported(descriptor: &MiniscriptDescriptor<PublicKey>) -> Result<(), WalletError> {
    match descriptor.desc_type() {
        DescriptorType::Pkh
        | DescriptorType::Wpkh
        | DescriptorType::ShWpkh
        | DescriptorType::Wsh
        | DescriptorType::Tr => Ok(()),
        other => Err(WalletError::Descriptor(format!(
            "unsupported descriptor type {other:?}"
        ))),
    }
}

/// What `getdescriptorinfo` reports about a descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorInfo {
    /// Canonical form, with private keys replaced by their public counterparts.
    ///
    /// For a multipath descriptor this is the first expansion, as Bitcoin Core
    /// documents.
    pub canonical: String,
    /// One entry per multipath expansion; empty for a single-path descriptor.
    pub multipath_expansion: Vec<String>,
    /// Whether the descriptor carries a `*`, and so describes a range.
    pub is_range: bool,
    /// Whether the descriptor carries enough information to produce a spend.
    pub is_solvable: bool,
    /// Whether the *input* carried at least one private key.
    pub has_private_keys: bool,
}

/// Analyses a descriptor without keeping anything private it carried.
///
/// The returned `canonical` form is derived from the parsed descriptor, whose
/// keys are public by construction: `parse_descriptor` hands the private key
/// material back separately, and this function keeps only the fact that there
/// was some. Echoing the caller's text back would return an `xprv` to whoever
/// asked, which is the one thing this call must not do.
///
/// # Errors
///
/// Returns [`WalletError::Descriptor`] when the text is not a descriptor.
pub fn analyse(text: &str) -> Result<DescriptorInfo, WalletError> {
    let secp = bitcoin::secp256k1::Secp256k1::signing_only();
    match MiniscriptDescriptor::<DescriptorPublicKey>::parse_descriptor(&secp, text) {
        Ok((descriptor, keys)) => {
            let multipath_expansion = if descriptor.is_multipath() {
                descriptor
                    .clone()
                    .into_single_descriptors()
                    .map_err(|error| WalletError::Descriptor(error.to_string()))?
                    .iter()
                    .map(ToString::to_string)
                    .collect()
            } else {
                Vec::new()
            };
            let canonical = multipath_expansion
                .first()
                .cloned()
                .unwrap_or_else(|| descriptor.to_string());
            Ok(DescriptorInfo {
                canonical,
                multipath_expansion,
                is_range: descriptor.has_wildcard(),
                is_solvable: true,
                has_private_keys: !keys.is_empty(),
            })
        }
        // `addr()` and `raw()` name an output without saying how to spend it,
        // so miniscript does not model them at all. They are still descriptors,
        // and Core reports them as the unsolvable ones they are rather than
        // refusing the question -- but it still checks that what is inside the
        // brackets is an address or a script, and so does this.
        Err(error) => match parse_unspendable(strip_checksum(text)) {
            Some(unspendable) => Ok(DescriptorInfo {
                canonical: unspendable?.canonical(),
                multipath_expansion: Vec::new(),
                is_range: false,
                is_solvable: false,
                has_private_keys: false,
            }),
            None => Err(WalletError::Descriptor(error.to_string())),
        },
    }
}

/// Derives the addresses a descriptor describes.
///
/// The outer vector is one entry per multipath expansion, in specifier order;
/// a single-path descriptor yields exactly one. `range` is inclusive at both
/// ends, matching Bitcoin Core.
///
/// # Errors
///
/// Returns [`WalletError::DescriptorRange`] when a range is required and
/// absent, or supplied for a descriptor that has no range, and
/// [`WalletError::Descriptor`] when the text does not parse or the descriptor
/// has no address form.
pub fn derive_addresses(
    text: &str,
    network: Network,
    range: Option<(u32, u32)>,
) -> Result<Vec<Vec<String>>, WalletError> {
    // An `addr()` or `raw()` descriptor has exactly one output and no range.
    if let Some(unspendable) = parse_unspendable(strip_checksum(text)) {
        if range.is_some() {
            return Err(WalletError::DescriptorRange(
                "Range should not be specified for an un-ranged descriptor",
            ));
        }
        return Ok(vec![vec![unspendable?.address(network)?]]);
    }

    let secp = bitcoin::secp256k1::Secp256k1::signing_only();
    let (descriptor, _keys) =
        MiniscriptDescriptor::<DescriptorPublicKey>::parse_descriptor(&secp, text)
            .map_err(|error| WalletError::Descriptor(error.to_string()))?;

    match (descriptor.has_wildcard(), range) {
        (true, None) => {
            return Err(WalletError::DescriptorRange(
                "Range must be specified for a ranged descriptor",
            ));
        }
        (false, Some(_)) => {
            return Err(WalletError::DescriptorRange(
                "Range should not be specified for an un-ranged descriptor",
            ));
        }
        _ => {}
    }

    let paths = if descriptor.is_multipath() {
        descriptor
            .into_single_descriptors()
            .map_err(|error| WalletError::Descriptor(error.to_string()))?
    } else {
        vec![descriptor]
    };

    let (begin, end) = range.unwrap_or((0, 0));
    let mut expansions = Vec::with_capacity(paths.len());
    for path in paths {
        let mut addresses = Vec::new();
        for index in begin..=end {
            let derived = path
                .at_derivation_index(index)
                .map_err(|error| WalletError::Descriptor(error.to_string()))?;
            let address = derived.address(network).map_err(|_error| {
                WalletError::Descriptor(
                    "Descriptor does not have a corresponding address".to_owned(),
                )
            })?;
            addresses.push(address.to_string());
        }
        expansions.push(addresses);
    }
    Ok(expansions)
}

/// A descriptor that names an output without saying how to spend it.
enum Unspendable {
    /// `addr(<address>)`.
    Address(Address<bitcoin::address::NetworkUnchecked>),
    /// `raw(<script hex>)`.
    Raw(bitcoin::ScriptBuf),
}

impl Unspendable {
    /// The descriptor re-encoded from what was parsed, not echoed back.
    fn canonical(&self) -> String {
        match self {
            Self::Address(address) => format!("addr({})", address.clone().assume_checked()),
            Self::Raw(script) => format!("raw({})", script.to_hex_string()),
        }
    }

    /// The address this output pays to, when it has one.
    fn address(&self, network: Network) -> Result<String, WalletError> {
        match self {
            Self::Address(address) => address
                .clone()
                .require_network(network)
                .map(|address| address.to_string())
                .map_err(|error| WalletError::Descriptor(error.to_string())),
            // Core's `ExtractDestination`: a raw script only has an address if
            // it is one of the standard forms.
            Self::Raw(script) => Address::from_script(script, network)
                .map(|address| address.to_string())
                .map_err(|_error| {
                    WalletError::Descriptor(
                        "Descriptor does not have a corresponding address".to_owned(),
                    )
                }),
        }
    }
}

/// Recognises `addr()` and `raw()`, and checks what is inside the brackets.
///
/// `None` means the text is not one of these two forms at all -- the caller
/// should report whatever the real descriptor parser said about it. `Some(Err)`
/// means it is one of them and the contents are not valid, which is a rejection
/// in its own right rather than a reason to fall through.
fn parse_unspendable(text: &str) -> Option<Result<Unspendable, WalletError>> {
    let body = text.strip_suffix(')')?;
    if let Some(address) = body.strip_prefix("addr(") {
        return Some(
            Address::from_str(address)
                .map(Unspendable::Address)
                .map_err(|error| WalletError::Descriptor(error.to_string())),
        );
    }
    let hex = body.strip_prefix("raw(")?;
    Some(
        bitcoin::ScriptBuf::from_hex(hex)
            .map(Unspendable::Raw)
            .map_err(|error| WalletError::Descriptor(error.to_string())),
    )
}

/// Drops a trailing `#checksum`, which is not part of the descriptor body.
fn strip_checksum(text: &str) -> &str {
    text.rsplit_once('#').map_or(text, |(body, _)| body)
}

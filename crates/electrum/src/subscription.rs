use bitcoin_rs_index::ScriptHash;
use compact_str::CompactString;
use hashbrown::HashMap;
use sonic_rs::{Value, json};

use crate::methods::{ElectrumError, IndexHandle, MempoolHandle, scripthash_hex, status_string};

const MAX_SCRIPTHASH_SUBSCRIPTIONS: usize = 256;

/// Per-session Electrum subscription state.
#[derive(Clone, Debug, Default)]
pub struct SessionSubscriptions {
    scripthashes: HashMap<ScriptHash, Option<CompactString>>,
    headers: Option<Value>,
}

impl SessionSubscriptions {
    /// Creates empty subscription state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a scripthash subscription at its current status.
    pub fn subscribe_scripthash(
        &mut self,
        index: &IndexHandle,
        mempool: &MempoolHandle,
        scripthash: ScriptHash,
    ) -> Result<Value, ElectrumError> {
        if !self.scripthashes.contains_key(&scripthash)
            && self.scripthashes.len() >= MAX_SCRIPTHASH_SUBSCRIPTIONS
        {
            return Err(ElectrumError::QueryTooLarge {
                resource: "scripthash-subscription",
                limit: MAX_SCRIPTHASH_SUBSCRIPTIONS,
            });
        }
        let status = status_string(index, mempool, scripthash)?;
        self.scripthashes.insert(scripthash, status.clone());
        Ok(status_value(status))
    }

    /// Removes the subscription for `scripthash`. Returns `true` if the
    /// scripthash was previously tracked (i.e., the unsubscribe had effect).
    ///
    /// No-op when the scripthash is not currently subscribed.
    pub fn unsubscribe_scripthash(&mut self, scripthash: ScriptHash) -> bool {
        self.scripthashes.remove(&scripthash).is_some()
    }

    /// Records a header subscription result returned to the client.
    pub fn subscribe_headers(&mut self, value: Value) {
        self.headers = Some(value);
    }

    /// Polls subscribed keys and returns JSON-RPC notifications for changed statuses.
    pub fn poll(
        &mut self,
        index: &IndexHandle,
        mempool: &MempoolHandle,
    ) -> Result<Vec<Value>, ElectrumError> {
        let mut observed: Vec<(ScriptHash, Option<CompactString>)> =
            Vec::with_capacity(self.scripthashes.len());
        for scripthash in self.scripthashes.keys().copied() {
            observed.push((scripthash, status_string(index, mempool, scripthash)?));
        }

        let mut notifications = Vec::new();
        for (scripthash, new_status) in observed {
            let Some(old_status) = self.scripthashes.get_mut(&scripthash) else {
                continue;
            };
            if *old_status != new_status {
                old_status.clone_from(&new_status);
                notifications.push(json!({
                    "jsonrpc": "2.0",
                    "method": "blockchain.scripthash.subscribe",
                    "params": [scripthash_hex(scripthash), status_value(new_status)],
                }));
            }
        }
        Ok(notifications)
    }

    /// Returns the number of tracked scripthash subscriptions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scripthashes.len()
    }

    /// Returns `true` when no scripthashes are subscribed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scripthashes.is_empty()
    }
}

/// Converts an optional Electrum status hash into its JSON value.
#[must_use]
pub fn status_value(status: Option<CompactString>) -> Value {
    match status {
        Some(status) => json!(status.as_str()),
        None => Value::new_null(),
    }
}

#[cfg(test)]
mod unsubscribe_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bitcoin::hashes::Hash as _;
    use bitcoin_rs_index::ScriptHash;

    use super::{MAX_SCRIPTHASH_SUBSCRIPTIONS, SessionSubscriptions};
    use crate::methods::{
        ConfirmedHistoryReader, ElectrumError, HistoryRecord, IndexHandle, MempoolHandle,
    };

    #[derive(Debug, Default)]
    struct FailSecondLookup {
        calls: AtomicUsize,
    }

    impl ConfirmedHistoryReader for FailSecondLookup {
        fn confirmed_history(&self, _: ScriptHash) -> Result<Vec<HistoryRecord>, ElectrumError> {
            if self.calls.fetch_add(1, Ordering::AcqRel) == 1 {
                return Err(ElectrumError::TxIndexUnavailable);
            }
            Ok(vec![HistoryRecord {
                txid: bitcoin::Txid::from_byte_array([0x42; 32]),
                height: 1,
                value: 0,
                vout: 0,
                spent: false,
            }])
        }
    }

    #[test]
    fn unsubscribe_scripthash_removes_existing_subscription() -> Result<(), ElectrumError> {
        let mut subs = SessionSubscriptions::new();
        let index = IndexHandle::new();
        let mempool = MempoolHandle::default();
        let sh = ScriptHash::from_byte_array([0xab_u8; 32]);

        let _status = subs.subscribe_scripthash(&index, &mempool, sh)?;

        assert!(subs.unsubscribe_scripthash(sh));
        assert!(!subs.unsubscribe_scripthash(sh));
        assert_eq!(subs.len(), 0);
        Ok(())
    }

    #[test]
    fn unsubscribe_scripthash_returns_false_for_untracked() {
        let mut subs = SessionSubscriptions::new();
        let sh = ScriptHash::from_byte_array([0xcd_u8; 32]);

        assert!(!subs.unsubscribe_scripthash(sh));
    }

    #[test]
    fn failed_poll_keeps_every_cached_status_unchanged() {
        let first = ScriptHash::from_byte_array([0x11; 32]);
        let second = ScriptHash::from_byte_array([0x22; 32]);
        let mut subs = SessionSubscriptions::new();
        subs.scripthashes.insert(first, None);
        subs.scripthashes.insert(second, None);
        let index = IndexHandle::new().with_history_reader(Arc::new(FailSecondLookup::default()));

        assert!(matches!(
            subs.poll(&index, &MempoolHandle::default()),
            Err(ElectrumError::TxIndexUnavailable)
        ));
        assert!(subs.scripthashes.values().all(Option::is_none));
    }

    #[test]
    fn subscription_limit_refuses_a_new_key_but_allows_refresh() {
        let mut subs = SessionSubscriptions::new();
        for value in 0..MAX_SCRIPTHASH_SUBSCRIPTIONS {
            let mut bytes = [0_u8; 32];
            bytes[..core::mem::size_of::<usize>()].copy_from_slice(&value.to_le_bytes());
            subs.scripthashes
                .insert(ScriptHash::from_byte_array(bytes), None);
        }
        let existing = *subs
            .scripthashes
            .keys()
            .next()
            .unwrap_or_else(|| panic!("subscription fixture is empty"));

        assert!(
            subs.subscribe_scripthash(&IndexHandle::new(), &MempoolHandle::default(), existing)
                .is_ok()
        );
        assert!(matches!(
            subs.subscribe_scripthash(
                &IndexHandle::new(),
                &MempoolHandle::default(),
                ScriptHash::from_byte_array([0xff; 32])
            ),
            Err(ElectrumError::QueryTooLarge {
                resource: "scripthash-subscription",
                limit: MAX_SCRIPTHASH_SUBSCRIPTIONS
            })
        ));
    }
}

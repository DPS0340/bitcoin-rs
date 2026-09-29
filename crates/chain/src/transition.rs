//! Transition exclusion: one domain, split into the two roles that serialize against it.

use parking_lot::{Mutex, MutexGuard};
use std::sync::Arc;

/// The one domain authoritative chain transitions and stable reads exclude each other through.
///
/// Composition mints this once per node and splits it into [`TransitionAuthority`]
/// for the mutation side and [`StableRead`] for readers. Neither role can mint a
/// domain of its own, so a reader cannot end up excluding transitions that no
/// chainstate performs: correctness comes from the wiring, not from comparing
/// domains after the fact.
///
/// The mutex itself never leaves this type. Callers receive roles, and roles
/// hand back guards, so no consumer can reach the shared cell or the other
/// role's protocol.
#[derive(Clone, Default)]
pub struct TransitionDomain {
    inner: Arc<Mutex<()>>,
}

impl TransitionDomain {
    /// Mints a fresh domain that no other component shares yet.
    ///
    /// Composition calls this once while opening a node; readers receive a role
    /// instead of constructing a domain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Splits off the mutation role: held across an authoritative chain transition.
    #[must_use]
    pub fn authority(&self) -> TransitionAuthority {
        TransitionAuthority {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Splits off the read role: held while a read must not observe a transition.
    #[must_use]
    pub fn stable_read(&self) -> StableRead {
        StableRead {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Mutation-side role: excludes stable reads for as long as a chain transition runs.
///
/// Held only by chainstate and by destructive pruning, which take it through
/// their own admission first. Readers never receive this type, so they cannot
/// enter the mutation-side lock order.
#[derive(Clone)]
pub struct TransitionAuthority {
    inner: Arc<Mutex<()>>,
}

impl TransitionAuthority {
    /// Excludes every stable read on this domain until the guard is dropped.
    pub fn lock(&self) -> TransitionAuthorityGuard<'_> {
        TransitionAuthorityGuard {
            _guard: self.inner.lock(),
        }
    }
}

/// Read-side role: excludes authoritative transitions for as long as a stable read runs.
///
/// This is the capability RPC, index, and mining receive. It offers `lock` and
/// `try_lock` and nothing else: no access to the shared cell, no path to a
/// [`TransitionAuthority`], and no way to mint a domain.
#[derive(Clone)]
pub struct StableRead {
    inner: Arc<Mutex<()>>,
}

impl StableRead {
    /// Excludes authoritative transitions until the returned guard is dropped.
    pub fn lock(&self) -> StableReadGuard<'_> {
        StableReadGuard {
            _guard: self.inner.lock(),
        }
    }

    /// Attempts the same exclusion without blocking, so a caller can fail fast
    /// instead of queueing behind a transition it cannot help finish.
    pub fn try_lock(&self) -> Option<StableReadGuard<'_>> {
        self.inner
            .try_lock()
            .map(|guard| StableReadGuard { _guard: guard })
    }
}

/// Proof that stable reads are excluded for as long as it lives.
///
/// The guard is opaque: dropping it is the only way to end the exclusion, so a
/// reader cannot release the fence early and re-open the window it closed.
pub struct TransitionAuthorityGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

/// Proof that authoritative transitions are excluded for as long as it lives.
pub struct StableReadGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

use parking_lot::Mutex;

use super::{WarningKind, Warnings};

/// `MetricsServer::bind` installs a process-global recorder. Serialize every
/// test that publishes or scrapes metrics so another test cannot change the
/// recorder mid-assertion. Production is unchanged.
pub(super) static SERVER_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn warnings_keep_first_message_and_report_in_kind_order() {
    let warnings = Warnings::new();
    assert!(warnings.messages().is_empty());

    assert!(warnings.set(WarningKind::ClockOutOfSync, "clock out of sync"));
    // Core ignores a later message for an already-active kind.
    assert!(!warnings.set(WarningKind::ClockOutOfSync, "superseded message"));
    assert!(warnings.set(WarningKind::FatalInternalError, "fatal"));
    assert!(warnings.set(WarningKind::UnknownNewRulesActivated, "unknown rules"));

    assert_eq!(
        warnings.messages(),
        [
            "unknown rules".to_owned(),
            "clock out of sync".to_owned(),
            "fatal".to_owned(),
        ],
        "kernel warnings must sort before node warnings regardless of set order"
    );

    assert!(warnings.unset(WarningKind::ClockOutOfSync));
    assert!(!warnings.unset(WarningKind::ClockOutOfSync));
    assert_eq!(
        warnings.messages(),
        ["unknown rules".to_owned(), "fatal".to_owned()]
    );
}

mod readiness;

mod server;

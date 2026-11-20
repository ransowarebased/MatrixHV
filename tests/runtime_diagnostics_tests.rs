use super::*;

#[test]
fn absent_and_legacy_diagnostics_never_authorize_transitions() {
    let absent = query_with(|_| [0; 4]);
    assert!(!absent.present);
    assert!(absent.transition_preflight("off", 1).is_err());
    let legacy = query_with(|_| {
        [
            MATRIXHV_STATUS_SIGNATURE_EAX,
            MATRIXHV_STATUS_SIGNATURE_EBX,
            MATRIXHV_STATUS_SIGNATURE_ECX,
            3,
        ]
    });
    assert!(legacy.present);
    assert!(!legacy.diagnostic_available);
    assert!(legacy.transition_preflight("update", 1).is_err());
}

#[test]
fn all_cpu_slots_including_high_mask_are_checked() {
    let state = query_with(|leaf| match leaf {
        0 => [
            MATRIXHV_STATUS_SIGNATURE_EAX,
            MATRIXHV_STATUS_SIGNATURE_EBX,
            MATRIXHV_STATUS_SIGNATURE_ECX,
            4,
        ],
        36 => [1, 1, 0, 0],
        31 => [1, 1, 0, 0],
        value if value == (31 | (33 << 16)) => [1, 0, 0, 0],
        _ => [0; 4],
    });
    assert_eq!(state.registered_mask, 1 | (1 << 32));
    assert_eq!(state.nested_mask, 1 << 32);
    assert!(state.caller_l2);
    assert!(
        state
            .transition_preflight("update", 1)
            .unwrap_err()
            .contains("native state handoff")
    );
    let native = RuntimeState {
        present: true,
        diagnostic_available: true,
        registered_mask: 1,
        ..RuntimeState::default()
    };
    assert!(native.transition_preflight("off", 1).is_ok());
    assert!(native.transition_preflight("off", 3).is_err());
}

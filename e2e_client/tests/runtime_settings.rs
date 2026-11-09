use e2e_client::harness::E2EHarness;
use hubuum_client::RuntimeSettingsPatch;
use serde_json::{Map, Value, json};

#[test]
#[ignore = "requires a disposable Hubuum integration server"]
fn discovered_runtime_setting_round_trip() {
    let harness = E2EHarness::from_env().unwrap();
    let admin = &harness.client;
    let catalogue = match admin.runtime_settings_schema() {
        Ok(catalogue) => catalogue,
        Err(error) if error.status().is_some_and(|status| status.as_u16() == 404) => {
            // Discovery is optional on the pinned release; exercise it on newer servers.
            return;
        }
        Err(error) => panic!("runtime settings discovery failed: {error}"),
    };
    assert_eq!(catalogue.schema_version, 1);
    assert!(
        catalogue
            .groups
            .iter()
            .any(|group| group.key == "pagination")
    );
    let original = admin.runtime_settings_group("pagination").unwrap();
    let revision = original.revision.expect("pagination has a revision");
    let next = if original.effective["default_page_limit"] == json!(75) {
        76
    } else {
        75
    };
    let changes: Map<String, Value> =
        serde_json::from_value(json!({"default_page_limit": next})).unwrap();
    let updated = admin
        .patch_runtime_settings(
            "pagination",
            RuntimeSettingsPatch::new(revision, changes.clone()).unwrap(),
        )
        .unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let state = admin.runtime_settings_group("pagination").unwrap();
        assert_eq!(state.effective["default_page_limit"], json!(next));
        let stale = admin
            .patch_runtime_settings(
                "pagination",
                RuntimeSettingsPatch::new(revision, changes).unwrap(),
            )
            .unwrap_err();
        assert_eq!(stale.status().unwrap().as_u16(), 412);
    }));
    if original.source == "deployment" {
        admin
            .release_runtime_settings("pagination", updated.committed_revision)
            .unwrap();
    } else {
        admin
            .patch_runtime_settings(
                "pagination",
                RuntimeSettingsPatch::new(updated.committed_revision, original.runtime.unwrap())
                    .unwrap(),
            )
            .unwrap();
    }
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

use l2_loop_core::{
    DeploymentArtifactIdentityV1, GI_AUTH_ARTIFACT, GI_AUTH_EXPIRED, GI_AUTH_HOST, GI_AUTH_SCHEMA,
    GI_BUNDLE_INVALID, GI_DESTINATION_FOREIGN, GI_INTERNAL, GI_LAYOUT_VERIFY, GI_METADATA_UNSAFE,
    GI_PHYSICAL_BLOCKED, GI_ROLLBACK_IDENTITY, GI_SERVICE_LIFECYCLE, GI_SERVICE_STATE,
    GI_TRANSACTION_CONFLICT, GI_WRITE_FAILED, INSTALL_AUTHORIZATION_MAX_LIFETIME_MS,
    INSTALLATION_SCHEMA_VERSION, InstallAuthorizationV1, InstallCommandV1, InstallDecisionV1,
    InstallFindingSeverityV1, InstallFindingV1, InstallOperationV1, InstallReportV1,
};
use serde_json::{Value, json};

const NOW_MS: u64 = 1_786_659_200_000;
const EXPIRES_MS: u64 = NOW_MS + INSTALL_AUTHORIZATION_MAX_LIFETIME_MS;
const AUTHORIZATION_ID: &str = "00112233445566778899aabbccddeeff";
const TRANSACTION_ID: &str = "ffeeddccbbaa99887766554433221100";
const COMMIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const MANIFEST_SHA256: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const HOST_SHA256: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DEPLOYMENT_AUTHORIZATION_SHA256: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
const PERFORMANCE_EVIDENCE_SHA256: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";

#[test]
fn installation_constants_and_public_values_are_fixed() {
    assert_eq!(INSTALLATION_SCHEMA_VERSION, 1);
    assert_eq!(INSTALL_AUTHORIZATION_MAX_LIFETIME_MS, 60 * 60 * 1_000);
    assert_eq!(InstallOperationV1::Install.to_string(), "install");
    assert_eq!(InstallOperationV1::Upgrade.to_string(), "upgrade");
    assert_eq!(InstallOperationV1::Rollback.to_string(), "rollback");
    assert_eq!(InstallDecisionV1::Blocked.to_string(), "blocked");
    assert_eq!(
        InstallDecisionV1::InstallPlanReady.to_string(),
        "install_plan_ready"
    );
    assert_eq!(
        InstallDecisionV1::InstalledVerified.to_string(),
        "installed_verified"
    );
    assert_eq!(InstallDecisionV1::RolledBack.to_string(), "rolled_back");
}

#[test]
fn authorization_json_is_strict() {
    let valid = valid_authorization_value();
    let parsed: InstallAuthorizationV1 = serde_json::from_value(valid.clone()).unwrap();
    parsed.validate_at(NOW_MS).unwrap();

    let mut unknown = valid.clone();
    unknown["destination_root"] = json!("/tmp/override");
    assert!(serde_json::from_value::<InstallAuthorizationV1>(unknown).is_err());

    let raw = serde_json::to_string(&valid).unwrap();
    let duplicate = raw.replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    assert!(serde_json::from_str::<InstallAuthorizationV1>(&duplicate).is_err());

    for field in [
        "schema_version",
        "authorization_id",
        "transaction_id",
        "operation",
        "artifact_commit_sha",
        "bundle_manifest_sha256",
        "host_identity_sha256",
        "deployment_authorization_sha256",
        "performance_evidence_sha256",
        "issued_at_unix_ms",
        "expires_at_unix_ms",
        "service_enable",
        "service_start",
        "physical_attach",
    ] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<InstallAuthorizationV1>(missing).is_err(),
            "accepted missing field {field}"
        );
    }

    let mut wrong_type = valid;
    wrong_type["expires_at_unix_ms"] = json!("1786659200000");
    assert!(serde_json::from_value::<InstallAuthorizationV1>(wrong_type).is_err());
}

#[test]
fn authorization_rejects_noncanonical_ids_commit_and_digests() {
    for (field, valid) in [
        ("authorization_id", AUTHORIZATION_ID),
        ("transaction_id", TRANSACTION_ID),
    ] {
        for invalid in [
            "",
            "00112233445566778899aabbccddeef",
            "00112233445566778899aabbccddeeff00",
            "00112233445566778899AABBCCDDEEFF",
            "../112233445566778899aabbccddeeff",
        ] {
            let mut value = valid_authorization_value();
            value[field] = json!(invalid);
            assert!(
                serde_json::from_value::<InstallAuthorizationV1>(value).is_err(),
                "accepted invalid {field} in place of {valid}"
            );
        }
    }

    for invalid in [
        "",
        "0123456789abcdef0123456789abcdef0123456",
        "0123456789abcdef0123456789abcdef012345678",
        "0123456789ABCDEF0123456789ABCDEF01234567",
        "../3456789abcdef0123456789abcdef01234567",
    ] {
        let mut value = valid_authorization_value();
        value["artifact_commit_sha"] = json!(invalid);
        assert!(serde_json::from_value::<InstallAuthorizationV1>(value).is_err());
    }

    for field in [
        "bundle_manifest_sha256",
        "host_identity_sha256",
        "deployment_authorization_sha256",
        "performance_evidence_sha256",
    ] {
        for invalid in [
            "",
            "111111111111111111111111111111111111111111111111111111111111111",
            "11111111111111111111111111111111111111111111111111111111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            let mut value = valid_authorization_value();
            value[field] = json!(invalid);
            assert!(
                serde_json::from_value::<InstallAuthorizationV1>(value).is_err(),
                "accepted invalid digest for {field}"
            );
        }
    }
}

#[test]
fn authorization_requires_fixed_false_authority_flags() {
    for field in ["service_enable", "service_start", "physical_attach"] {
        let mut value = valid_authorization_value();
        value[field] = json!(true);
        let parsed: InstallAuthorizationV1 = serde_json::from_value(value).unwrap();
        assert!(parsed.validate_at(NOW_MS).is_err(), "accepted true {field}");
    }
}

#[test]
fn authorization_lifetime_is_positive_bounded_and_inclusive() {
    let authorization = valid_authorization();
    authorization.validate_at(NOW_MS).unwrap();
    authorization.validate_at(EXPIRES_MS).unwrap();
    assert!(authorization.validate_at(NOW_MS - 1).is_err());
    assert!(authorization.validate_at(EXPIRES_MS + 1).is_err());

    for (issued, expires) in [
        (NOW_MS, NOW_MS),
        (NOW_MS + 1, NOW_MS),
        (NOW_MS, EXPIRES_MS + 1),
        (0, EXPIRES_MS),
    ] {
        let mut value = valid_authorization_value();
        value["issued_at_unix_ms"] = json!(issued);
        value["expires_at_unix_ms"] = json!(expires);
        let parsed: InstallAuthorizationV1 = serde_json::from_value(value).unwrap();
        assert!(parsed.validate_at(NOW_MS).is_err());
    }
}

#[test]
fn authorization_binds_every_exact_installation_input() {
    let authorization = valid_authorization();
    authorization
        .validate_for(
            NOW_MS,
            InstallOperationV1::Install,
            &artifact(),
            MANIFEST_SHA256,
            HOST_SHA256,
            DEPLOYMENT_AUTHORIZATION_SHA256,
            PERFORMANCE_EVIDENCE_SHA256,
        )
        .unwrap();

    let alternate_artifact =
        DeploymentArtifactIdentityV1::new("1123456789abcdef0123456789abcdef01234567", "0.1.0")
            .unwrap();
    assert!(
        authorization
            .validate_for(
                NOW_MS,
                InstallOperationV1::Install,
                &alternate_artifact,
                MANIFEST_SHA256,
                HOST_SHA256,
                DEPLOYMENT_AUTHORIZATION_SHA256,
                PERFORMANCE_EVIDENCE_SHA256,
            )
            .is_err()
    );

    let wrong_digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for digests in [
        (
            wrong_digest,
            HOST_SHA256,
            DEPLOYMENT_AUTHORIZATION_SHA256,
            PERFORMANCE_EVIDENCE_SHA256,
        ),
        (
            MANIFEST_SHA256,
            wrong_digest,
            DEPLOYMENT_AUTHORIZATION_SHA256,
            PERFORMANCE_EVIDENCE_SHA256,
        ),
        (
            MANIFEST_SHA256,
            HOST_SHA256,
            wrong_digest,
            PERFORMANCE_EVIDENCE_SHA256,
        ),
        (
            MANIFEST_SHA256,
            HOST_SHA256,
            DEPLOYMENT_AUTHORIZATION_SHA256,
            wrong_digest,
        ),
    ] {
        assert!(
            authorization
                .validate_for(
                    NOW_MS,
                    InstallOperationV1::Install,
                    &artifact(),
                    digests.0,
                    digests.1,
                    digests.2,
                    digests.3,
                )
                .is_err()
        );
    }

    assert!(
        authorization
            .validate_for(
                NOW_MS,
                InstallOperationV1::Upgrade,
                &artifact(),
                MANIFEST_SHA256,
                HOST_SHA256,
                DEPLOYMENT_AUTHORIZATION_SHA256,
                PERFORMANCE_EVIDENCE_SHA256,
            )
            .is_err()
    );
}

#[test]
fn authorization_rejects_unknown_operation() {
    let mut value = valid_authorization_value();
    value["operation"] = json!("uninstall");
    assert!(serde_json::from_value::<InstallAuthorizationV1>(value).is_err());
}

#[test]
fn findings_accept_only_stable_codes_and_sort_deterministically() {
    let codes = [
        GI_AUTH_SCHEMA,
        GI_AUTH_EXPIRED,
        GI_AUTH_HOST,
        GI_AUTH_ARTIFACT,
        GI_BUNDLE_INVALID,
        GI_DESTINATION_FOREIGN,
        GI_METADATA_UNSAFE,
        GI_TRANSACTION_CONFLICT,
        GI_WRITE_FAILED,
        GI_ROLLBACK_IDENTITY,
        GI_LAYOUT_VERIFY,
        GI_SERVICE_STATE,
        GI_SERVICE_LIFECYCLE,
        GI_PHYSICAL_BLOCKED,
        GI_INTERNAL,
    ];
    for code in codes {
        assert_eq!(InstallFindingV1::blocker(code).unwrap().code, code);
        assert_eq!(InstallFindingV1::warning(code).unwrap().code, code);
    }
    assert!(InstallFindingV1::blocker("GI_CALLER_TEXT").is_err());

    let mut findings = vec![
        InstallFindingV1::warning(GI_INTERNAL).unwrap(),
        InstallFindingV1::blocker(GI_WRITE_FAILED).unwrap(),
        InstallFindingV1::blocker(GI_AUTH_SCHEMA).unwrap(),
        InstallFindingV1::blocker(GI_AUTH_SCHEMA).unwrap(),
    ];
    InstallFindingV1::sort_and_deduplicate(&mut findings);
    assert_eq!(findings.len(), 3);
    assert_eq!(findings[0].severity, InstallFindingSeverityV1::Blocker);
    assert_eq!(findings[0].code, GI_AUTH_SCHEMA);
    assert_eq!(findings[1].severity, InstallFindingSeverityV1::Blocker);
    assert_eq!(findings[1].code, GI_WRITE_FAILED);
    assert_eq!(findings[2].severity, InstallFindingSeverityV1::Warning);
    assert_eq!(findings[2].code, GI_INTERNAL);
}

#[test]
fn report_derives_only_command_appropriate_positive_states() {
    let plan = InstallReportV1::derive(
        InstallCommandV1::Plan,
        InstallOperationV1::Install,
        AUTHORIZATION_ID,
        TRANSACTION_ID,
        artifact(),
        Vec::new(),
        NOW_MS,
        false,
    )
    .unwrap();
    assert_eq!(plan.decision, InstallDecisionV1::InstallPlanReady);
    assert!(!plan.mutations_performed);
    plan.validate().unwrap();

    let apply = InstallReportV1::derive(
        InstallCommandV1::Apply,
        InstallOperationV1::Install,
        AUTHORIZATION_ID,
        TRANSACTION_ID,
        artifact(),
        Vec::new(),
        NOW_MS,
        true,
    )
    .unwrap();
    assert_eq!(apply.decision, InstallDecisionV1::InstalledVerified);
    assert!(apply.mutations_performed);
    apply.validate().unwrap();

    let status = InstallReportV1::derive(
        InstallCommandV1::Status,
        InstallOperationV1::Install,
        AUTHORIZATION_ID,
        TRANSACTION_ID,
        artifact(),
        Vec::new(),
        NOW_MS,
        false,
    )
    .unwrap();
    assert_eq!(status.decision, InstallDecisionV1::InstalledVerified);
    assert!(!status.mutations_performed);
    status.validate().unwrap();

    let rollback = InstallReportV1::derive(
        InstallCommandV1::Rollback,
        InstallOperationV1::Rollback,
        AUTHORIZATION_ID,
        TRANSACTION_ID,
        artifact(),
        Vec::new(),
        NOW_MS,
        true,
    )
    .unwrap();
    assert_eq!(rollback.decision, InstallDecisionV1::RolledBack);
    assert!(rollback.mutations_performed);
    rollback.validate().unwrap();
}

#[test]
fn report_blocks_on_any_blocker_and_rejects_shape_mismatches() {
    let blocked = InstallReportV1::derive(
        InstallCommandV1::Plan,
        InstallOperationV1::Install,
        AUTHORIZATION_ID,
        TRANSACTION_ID,
        artifact(),
        vec![InstallFindingV1::blocker(GI_AUTH_HOST).unwrap()],
        NOW_MS,
        false,
    )
    .unwrap();
    assert_eq!(blocked.decision, InstallDecisionV1::Blocked);
    blocked.validate().unwrap();

    for (command, operation, mutations) in [
        (InstallCommandV1::Plan, InstallOperationV1::Install, true),
        (InstallCommandV1::Apply, InstallOperationV1::Install, false),
        (InstallCommandV1::Status, InstallOperationV1::Install, true),
        (
            InstallCommandV1::Rollback,
            InstallOperationV1::Install,
            true,
        ),
        (
            InstallCommandV1::Rollback,
            InstallOperationV1::Rollback,
            false,
        ),
    ] {
        assert!(
            InstallReportV1::derive(
                command,
                operation,
                AUTHORIZATION_ID,
                TRANSACTION_ID,
                artifact(),
                Vec::new(),
                NOW_MS,
                mutations,
            )
            .is_err()
        );
    }
}

#[test]
fn installation_contract_is_bounded_and_cannot_grant_service_or_network_authority() {
    let authorization = valid_authorization();
    let value = serde_json::to_value(&authorization).unwrap();
    assert_eq!(value["service_enable"], false);
    assert_eq!(value["service_start"], false);
    assert_eq!(value["physical_attach"], false);

    let report = InstallReportV1::derive(
        InstallCommandV1::Plan,
        InstallOperationV1::Install,
        AUTHORIZATION_ID,
        TRANSACTION_ID,
        artifact(),
        Vec::new(),
        NOW_MS,
        false,
    )
    .unwrap();
    let rendered = serde_json::to_string(&report).unwrap();
    for prohibited in [
        "destination_root",
        "interface_name",
        "systemctl",
        "attach_endpoint",
        "execute_command",
        "raw_machine_id",
        "source_path",
        "error_chain",
    ] {
        assert!(
            !rendered.contains(prohibited),
            "report exposed {prohibited}"
        );
    }

    let retired_keyword = ["c", "s", "m", "p"].concat();
    assert!(!rendered.to_ascii_lowercase().contains(&retired_keyword));
    assert!(rendered.len() < 1_048_576);
}

fn artifact() -> DeploymentArtifactIdentityV1 {
    DeploymentArtifactIdentityV1::new(COMMIT_SHA, "0.1.0").unwrap()
}

fn valid_authorization() -> InstallAuthorizationV1 {
    serde_json::from_value(valid_authorization_value()).unwrap()
}

fn valid_authorization_value() -> Value {
    json!({
        "schema_version": 1,
        "authorization_id": AUTHORIZATION_ID,
        "transaction_id": TRANSACTION_ID,
        "operation": "install",
        "artifact_commit_sha": COMMIT_SHA,
        "bundle_manifest_sha256": MANIFEST_SHA256,
        "host_identity_sha256": HOST_SHA256,
        "deployment_authorization_sha256": DEPLOYMENT_AUTHORIZATION_SHA256,
        "performance_evidence_sha256": PERFORMANCE_EVIDENCE_SHA256,
        "issued_at_unix_ms": NOW_MS,
        "expires_at_unix_ms": EXPIRES_MS,
        "service_enable": false,
        "service_start": false,
        "physical_attach": false
    })
}

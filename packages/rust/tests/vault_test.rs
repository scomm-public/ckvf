use scomm_vault::*;
use serde_json::json;

const PASSWORD: &str = "CKVF-TEST-PASSWORD";
const NOW: &str = "2026-08-17T00:00:00Z";

#[test]
fn create_serialize_open_identity_generation() {
    let created = create_vault(CreateVaultOptions {
        identity_type: "email",
        identity_value: "Alice@Example.COM",
        password: Some(PASSWORD),
        now: Some(NOW),
        kdf: Some(TEST_ARGON2ID),
        vault_id: None,
        msk_seed: None,
        extensions: vec![],
        extra_slots: None,
    })
    .unwrap();
    assert_eq!(created.payload.identity.value, "alice@example.com");
    assert_eq!(created.container.generation, 1);
    assert!(created.container.previous_generation_hash.is_none());

    let json = serialize_container(&created.container).unwrap();
    let meta = inspect_public_metadata(&serde_json::from_str(&json).unwrap()).unwrap();
    assert_eq!(meta["format"], "CKVF");
    assert!(!meta.to_string().contains("alice@example.com"));

    let opened = open_vault_str(&json, PASSWORD, None, None).unwrap();
    assert!(opened.payload.keys.is_empty());
    assert_eq!(
        opened.payload.identity.identity_id,
        created.payload.identity.identity_id
    );
}

#[test]
fn wrong_password_fails() {
    let created = create("email", "alice@example.com", PASSWORD, Some(NOW)).unwrap();
    let err = open_vault(
        &created.container.to_json(),
        "wrong",
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(err.code(), "ERR_WRAP_DECRYPT");
}

#[test]
fn generation_hash_validates() {
    let created = create("email", "bob@example.com", PASSWORD, Some(NOW)).unwrap();
    validate(&created.container).unwrap();
    let mut bad = created.container.clone();
    bad.generation_hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
    assert_eq!(validate(&bad).unwrap_err().code(), "ERR_GENERATION_HASH");
}

#[test]
fn merge_of_two_vaults() {
    let a = create("email", "alice@example.com", PASSWORD, Some(NOW)).unwrap();
    let left = add_test_openpgp_key(&a, Some(NOW)).unwrap();
    let right = add_test_pkcs8_key(&a, Some(NOW)).unwrap();
    let merged = merge_vaults(&left, &right, Some(NOW)).unwrap();
    assert_eq!(merged.payload.keys.len(), 2);
    assert_eq!(
        merged.container.generation,
        left.container.generation.max(right.container.generation) + 1
    );

    let json = serialize_container(&merged.container).unwrap();
    let opened = open_vault_str(&json, PASSWORD, None, None).unwrap();
    assert_eq!(opened.payload.keys.len(), 2);
}

#[test]
fn jcs_and_aad_match_dart() {
    assert_eq!(
        canonicalize(&json!({"b": 1, "a": 2})).unwrap(),
        r#"{"a":2,"b":1}"#
    );
    let container = VaultContainer {
        format: "CKVF".into(),
        version: "1.0".into(),
        vault_id: "ASNFZ4mrze8BI0VniavN7w".into(),
        generation: 1,
        previous_generation_hash: None,
        generation_hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        crypto: CryptoParams {
            aead: "A256GCM".into(),
            iv: "AAECAwQFBgcICQoL".into(),
        },
        unlock_slots: vec![],
        ciphertext: String::new(),
        tag: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        extensions: vec![],
        critical_extensions: vec![],
    };
    assert_eq!(
        canonicalize(&aad_object(&container)).unwrap(),
        r#"{"critical_extensions":[],"crypto":{"aead":"A256GCM","iv":"AAECAwQFBgcICQoL"},"extensions":[],"format":"CKVF","generation":1,"previous_generation_hash":null,"unlock_slots":[],"vault_id":"ASNFZ4mrze8BI0VniavN7w","version":"1.0"}"#
    );
}

#[test]
fn email_dns_and_identity_id() {
    assert_eq!(
        canonicalize_email("User@Example.COM").unwrap(),
        "user@example.com"
    );
    assert_eq!(
        canonicalize_email("  alice@EXAMPLE.com  ").unwrap(),
        "alice@example.com"
    );
    assert_eq!(canonicalize_dns("Example.COM.").unwrap(), "example.com");
    assert_eq!(
        identity_id("email", "user@example.com"),
        "tmwIJmeStJDSo9giG47rc8MKlVNxXPBKhG1GIcReptA"
    );
    assert_eq!(
        identity_id("dns", "example.com"),
        "LpMoG_ozO2qxNonqsDwgJUBJEvma97aY8Z9q1njrZ-M"
    );
}

#[test]
fn short_key_id_and_capabilities() {
    assert_eq!(
        short_key_id_from_digest(&[0x64, 0x8a, 0xa5, 0xc5, 0, 0, 0, 0]).unwrap(),
        "648A-A5C5"
    );
    assert!(can_read_version("1.0"));
    assert!(can_write_version("1.0"));
    assert!(!can_read_version("2.0"));
    assert!(supported_unlock_methods().contains(&"password-argon2id"));
    assert_eq!(MSK_ALGORITHMS, &["Ed25519"]);
    assert!(is_forbidden_family("pq"));
    assert_eq!(algorithm_suite_from_algorithm("Ed25519"), Some("ecc"));
    assert_eq!(
        algorithm_suite_from_algorithm("ML-DSA-65+Ed25519"),
        Some("pqc")
    );
}

#[test]
fn merge_unions_keys_and_escalates_status() {
    fn key(id: &str, status: &str) -> KeyRecord {
        KeyRecord {
            absolute_key_id: id.into(),
            short_key_id: "0000-0000".into(),
            family: "openpgp".into(),
            algorithm: "Ed25519".into(),
            algorithm_suite: None,
            encoding: "openpgp-tsk".into(),
            purpose: vec!["sign".into()],
            public_key: "AA".into(),
            private_key: Some("BB".into()),
            created_at: NOW.into(),
            status: status.into(),
            metadata: serde_json::Map::new(),
        }
    }
    fn payload(keys: Vec<KeyRecord>) -> VaultPayload {
        VaultPayload {
            identity: Identity {
                r#type: "email".into(),
                value: "a@example.com".into(),
                identity_id: "x".into(),
            },
            msk: MskState {
                current: MskCurrent {
                    msk_id: "m".into(),
                    algorithm: "Ed25519".into(),
                    public_key: "p".into(),
                    private_key: "s".into(),
                    activated_at: NOW.into(),
                },
                history: vec![],
            },
            keys,
            preferred_keys: serde_json::Map::new(),
            metadata: VaultMetadata {
                created_at: NOW.into(),
                updated_at: NOW.into(),
            },
            tombstones: vec![],
            extensions: vec![],
            critical_extensions: vec![],
        }
    }
    let merged = merge_payloads(
        &payload(vec![
            key("K1", "active"),
            key("K2", "active"),
            key("K3", "active"),
        ]),
        &payload(vec![
            key("K1", "retired"),
            key("K2", "active"),
            key("K4", "active"),
        ]),
        &[],
        &[],
        0,
        0,
    )
    .unwrap();
    let mut ids: Vec<_> = merged
        .payload
        .keys
        .iter()
        .map(|k| k.absolute_key_id.clone())
        .collect();
    ids.sort();
    assert_eq!(ids, vec!["K1", "K2", "K3", "K4"]);
    assert_eq!(
        merged
            .payload
            .keys
            .iter()
            .find(|k| k.absolute_key_id == "K1")
            .unwrap()
            .status,
        "retired"
    );
}

#[test]
fn openpgp_and_pkcs8_plus_retire() {
    let mut vault = create("email", "alice@example.com", PASSWORD, Some(NOW)).unwrap();
    vault = add_test_openpgp_key(&vault, Some(NOW)).unwrap();
    vault = add_test_pkcs8_key(&vault, Some(NOW)).unwrap();
    assert_eq!(vault.payload.keys.len(), 2);
    let pgp_id = vault
        .payload
        .keys
        .iter()
        .find(|k| k.family == "openpgp")
        .unwrap()
        .absolute_key_id
        .clone();
    assert!(!export_private_key(&vault, &pgp_id).unwrap().is_empty());
    vault = retire_key(&vault, &pgp_id, Some(NOW)).unwrap();
    assert_eq!(
        vault
            .payload
            .keys
            .iter()
            .find(|k| k.absolute_key_id == pgp_id)
            .unwrap()
            .status,
        "retired"
    );
    let reopened = open_vault_str(
        &serialize_container(&vault.container).unwrap(),
        PASSWORD,
        None,
        None,
    )
    .unwrap();
    assert_eq!(reopened.payload.keys.len(), 2);
}

#[test]
fn facade_create_encrypt_decrypt() {
    let unlocked = create("email", "bob@example.com", PASSWORD, Some(NOW)).unwrap();
    let locked = encrypt(&unlocked).unwrap();
    let opened = decrypt(&serialize_container(&locked).unwrap(), PASSWORD).unwrap();
    assert_eq!(opened.payload.identity.value, "bob@example.com");
}

#[test]
fn openpgp_alg30_public_material_length() {
    let mut body = vec![0u8; 6 + 32 + 1952];
    body[0] = 4;
    body[5] = 30;
    let tsk = encode_new_format_packet(5, &body);
    let pub_key = canonical_openpgp_public_key(&[], Some(&tsk)).unwrap();
    assert_eq!(pub_key[0] & 0x3f, 6);
}

//! `eddsa-rdfc-2022` pinned by the W3C EdDSA Cryptosuites v1.0 vectors, and an Open Badges 3.0
//! credential issued and verified here. No network: contexts come from ikigai-jsonld's pins.

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use ikigai_credential::{canonicalize, hash_data, issue, verify, ProofOptions, Signer, Verdict};
use ikigai_sign::multikey::{multibase_decode, multibase_encode, multikey_decode};
use serde_json::{json, Value};

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vector/w3c-eddsa-rdfc-2022/"
);

fn vector(name: &str) -> String {
    std::fs::read_to_string(format!("{VECTOR}{name}")).unwrap()
}

fn vector_keys() -> (SigningKey, VerifyingKey) {
    let pair: Value = serde_json::from_str(&vector("keyPair.json")).unwrap();
    let secret = multibase_decode(pair["privateKeyMultibase"].as_str().unwrap()).unwrap();
    assert_eq!(
        &secret[..2],
        &[0x80, 0x26],
        "the Ed25519 private-key multicodec"
    );
    let signing = SigningKey::from_bytes(secret[2..].try_into().unwrap());
    let public = multikey_decode(pair["publicKeyMultibase"].as_str().unwrap()).unwrap();
    assert_eq!(signing.verifying_key(), public);
    (signing, public)
}

struct Key(SigningKey);
impl Signer for Key {
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.0.sign(message).to_bytes())
    }
}

#[test]
fn w3c_vector_proof_configuration_canonicalizes_to_the_published_nquads() {
    // The vector's proof configuration also names the examples context, which defines no proof
    // term and which ikigai-jsonld does not pin; the VC 2.0 context alone gives the same graph.
    let mut config: Value = serde_json::from_str(&vector("proofConfigDataInt.json")).unwrap();
    config["@context"] = json!(["https://www.w3.org/ns/credentials/v2"]);
    assert_eq!(
        canonicalize(&config).unwrap(),
        vector("proofCanonDataInt.txt")
    );
}

#[test]
fn w3c_vector_hash_and_signature_match_the_published_values() {
    let combined = hash_data(
        &vector("proofCanonDataInt.txt"),
        &vector("canonDocDataInt.txt"),
    );
    let hex: String = combined.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, vector("combinedHashDataInt.txt").trim());
    let (signing, public) = vector_keys();
    let signature = Key(signing).sign(&combined).unwrap();
    assert_eq!(
        multibase_encode(&signature),
        vector("sigBTC58DataInt.txt").trim()
    );
    let signed: Value = serde_json::from_str(&vector("signedDataInt.json")).unwrap();
    assert_eq!(
        signed["proof"]["proofValue"],
        vector("sigBTC58DataInt.txt").trim()
    );
    public
        .verify_strict(&combined, &ed25519_dalek::Signature::from_bytes(&signature))
        .unwrap();
}

/// An Open Badges 3.0 `OpenBadgeCredential`, every node with an id. The persistent IRI uses the
/// learning host's template with opaque ids.
fn badge() -> Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
        ],
        "id": "https://iriref.org/learn/student/id/s-7f3a/certificate/id/c-91d2",
        "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "name": "Introduction to RDF",
        "issuer": {
            "id": "did:web:iriref.org",
            "type": ["Profile"],
            "name": "iriref.org",
            "url": "https://iriref.org/"
        },
        "validFrom": "2026-11-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "type": ["AchievementSubject"],
            "achievement": {
                "id": "urn:credential:achievement:course:rdf-intro:release:2026-1",
                "type": ["Achievement"],
                "name": "Introduction to RDF",
                "description": "Completed the course's exercises with evidence and met its mastery rules, self-paced.",
                "criteria": {
                    "id": "urn:credential:achievement:course:rdf-intro:release:2026-1:criteria",
                    "narrative": "Complete every unit's exercises and meet each unit's mastery rule."
                }
            }
        }
    })
}

fn options() -> ProofOptions {
    ProofOptions {
        created: "2026-11-27T00:00:00Z".into(),
        verification_method: "did:web:iriref.org#key-1".into(),
        proof_purpose: "assertionMethod".into(),
    }
}

fn keys() -> (Key, VerifyingKey) {
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let public = signing.verifying_key();
    (Key(signing), public)
}

fn check(secured: &Value, now: &str, public: VerifyingKey) -> Verdict {
    verify(secured.to_string().as_bytes(), now, |method, valid_from| {
        assert_eq!(method, "did:web:iriref.org#key-1");
        assert_eq!(valid_from, Some("2026-11-01T00:00:00Z"));
        Ok(public)
    })
    .unwrap()
}

#[test]
fn an_open_badge_issued_here_verifies_here() {
    let (signer, public) = keys();
    let secured = issue(&badge(), &options(), &signer).unwrap();
    assert_eq!(secured["proof"]["cryptosuite"], "eddsa-rdfc-2022");
    assert!(secured["proof"]["proofValue"]
        .as_str()
        .unwrap()
        .starts_with('z'));
    assert_eq!(
        check(&secured, "2026-11-27T12:00:00Z", public),
        Verdict::Valid
    );
}

#[test]
fn issued_badge_canonicalizes_in_json_ld_safe_mode_with_no_blank_nodes() {
    // The 1EdTech Open Badges 3.0 certification guide, 1.3: the badge processes in JSON-LD
    // safe mode. Every term expands through the pinned contexts, and no node is blank.
    let nquads = canonicalize(&badge()).unwrap();
    assert!(!nquads.contains("_:"), "{nquads}");
    assert!(
        nquads.contains("<https://purl.imsglobal.org/spec/vc/ob/vocab.html#OpenBadgeCredential>")
    );
}

#[test]
fn a_changed_badge_does_not_verify() {
    let (signer, public) = keys();
    let mut secured = issue(&badge(), &options(), &signer).unwrap();
    secured["name"] = json!("Advanced RDF");
    assert!(matches!(
        check(&secured, "2026-11-27T12:00:00Z", public),
        Verdict::Invalid(_)
    ));
}

#[test]
fn another_key_does_not_verify() {
    let (signer, _) = keys();
    let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
    let secured = issue(&badge(), &options(), &signer).unwrap();
    assert!(matches!(
        check(&secured, "2026-11-27T12:00:00Z", other),
        Verdict::Invalid(_)
    ));
}

#[test]
fn the_validity_window_is_checked() {
    let (signer, public) = keys();
    let mut unsecured = badge();
    unsecured["validUntil"] = json!("2027-01-01T00:00:00Z");
    let secured = issue(&unsecured, &options(), &signer).unwrap();
    assert_eq!(
        check(&secured, "2026-12-01T00:00:00Z", public),
        Verdict::Valid
    );
    let early = check(&secured, "2026-10-01T00:00:00Z", public);
    assert_eq!(
        early.sentence(),
        "The credential is not valid: its validity period has not started yet."
    );
    let late = check(&secured, "2027-02-01T00:00:00Z", public);
    assert_eq!(
        late.sentence(),
        "The credential is not valid: its validity period has ended."
    );
}

#[test]
fn safe_mode_refuses_an_undefined_term() {
    let (signer, _) = keys();
    let mut unsecured = badge();
    unsecured["favoriteColor"] = json!("green");
    let err = issue(&unsecured, &options(), &signer).unwrap_err();
    eprintln!("{err}");
    assert!(matches!(err, ikigai_credential::Error::Input(_)), "{err}");
}

#[test]
fn a_node_without_an_id_is_refused() {
    let (signer, _) = keys();
    let mut unsecured = badge();
    unsecured["credentialSubject"]["achievement"]["criteria"]
        .as_object_mut()
        .unwrap()
        .remove("id");
    let err = issue(&unsecured, &options(), &signer).unwrap_err();
    assert_eq!(
        err.to_string(),
        "The credential has a node without an id; give every node an id before issuing."
    );
}

#[test]
fn an_unpinned_context_is_refused_without_a_fetch() {
    let (signer, _) = keys();
    let mut unsecured = badge();
    unsecured["@context"] = json!([
        "https://www.w3.org/ns/credentials/v2",
        "https://example.com/ctx"
    ]);
    let err = issue(&unsecured, &options(), &signer).unwrap_err();
    eprintln!("{err}");
    assert!(matches!(err, ikigai_credential::Error::Input(_)), "{err}");
}

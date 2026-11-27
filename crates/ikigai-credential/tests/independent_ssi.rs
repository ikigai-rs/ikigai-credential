//! Interoperability with an independent implementation: SpruceID's `ssi` (a dev-dependency).
//!
//! Both directions, with no network: a badge issued here verifies in `ssi`, and a badge `ssi`
//! signs with `eddsa-rdfc-2022` verifies here. `ssi` resolves `did:web:iriref.org` from a static
//! DID document built in this file (its `http-did` feature, which would fetch, is off), and reads
//! JSON-LD contexts through ikigai-jsonld's pinned, offline loader: `ssi`'s own static loader
//! pins the Open Badges context only at 3.0.0, not the 3.0.3 these badges name. Canonicalization,
//! hashing and the signature check are `ssi`'s own throughout.

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use ikigai_credential::{issue, verify, ProofOptions, Signer, Verdict};
use ikigai_jsonld::PinnedContextLoader;
use ikigai_sign::multikey::multikey_encode;
use serde_json::{json, Value};
use ssi::claims::chrono::{DateTime, Utc};
use ssi::claims::data_integrity::{AnySuite, CryptographicSuite, DataIntegrity};
use ssi::claims::vc::v2::syntax::JsonCredential;
use ssi::claims::{SignatureEnvironment, VerificationParameters};
use ssi::dids::{DIDResolver, StaticDIDResolver};
use ssi::prelude::{AnyMethod, SingleSecretSigner, JWK};
use ssi::verification_methods::ReferenceOrOwned;

const ISSUER: &str = "did:web:iriref.org";
const METHOD: &str = "did:web:iriref.org#key-1";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// The issuer's `did:web` document: one Multikey, for assertions.
fn did_document(public: &VerifyingKey) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": ISSUER,
        "verificationMethod": [{
            "id": METHOD,
            "type": "Multikey",
            "controller": ISSUER,
            "publicKeyMultibase": multikey_encode(public)
        }],
        "assertionMethod": [METHOD]
    })
}

fn resolver(public: &VerifyingKey) -> StaticDIDResolver {
    let mut resolver = StaticDIDResolver::new();
    resolver.insert(
        ISSUER.parse().unwrap(),
        ssi::dids::resolution::Output::from_content(
            did_document(public).to_string().into_bytes(),
            Some("application/did+json".to_owned()),
        ),
    );
    resolver
}

/// An Open Badges 3.0 `OpenBadgeCredential`, every node with an id, as the issue Sink makes it.
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
            "id": ISSUER,
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

fn clock() -> DateTime<Utc> {
    "2026-11-27T12:00:00Z".parse().unwrap()
}

struct Key(SigningKey);
impl Signer for Key {
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.0.sign(message).to_bytes())
    }
}

/// `Ok(())` when `ssi` verifies `secured`, its reason otherwise.
async fn ssi_verifies(secured: &Value, public: &VerifyingKey) -> Result<(), String> {
    let vc: DataIntegrity<JsonCredential, AnySuite> =
        serde_json::from_value(secured.clone()).map_err(|e| e.to_string())?;
    let params =
        VerificationParameters::from_resolver(resolver(public).into_vm_resolver::<AnyMethod>())
            .with_json_ld_loader(PinnedContextLoader)
            .with_date_time(clock());
    vc.verify(&params)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("{e:?}"))
}

#[tokio::test]
async fn a_badge_issued_here_verifies_in_ssi() {
    let signing = signing_key();
    let public = signing.verifying_key();
    let options = ProofOptions {
        created: "2026-11-27T00:00:00Z".into(),
        verification_method: METHOD.into(),
        proof_purpose: "assertionMethod".into(),
    };
    let secured = issue(&badge(), &options, &Key(signing)).unwrap();
    assert_eq!(ssi_verifies(&secured, &public).await, Ok(()));

    // The negative control: the same verifier refuses the badge once a claim is changed.
    let mut changed = secured.clone();
    changed["name"] = "Advanced RDF".into();
    assert!(ssi_verifies(&changed, &public).await.is_err());
}

#[tokio::test]
async fn a_badge_ssi_signs_verifies_here() {
    let signing = signing_key();
    let public = signing.verifying_key();
    let jwk = JWK::from(ssi::jwk::Params::OKP(ssi::jwk::OctetParams {
        curve: "Ed25519".to_owned(),
        public_key: ssi::jwk::Base64urlUInt(public.to_bytes().to_vec()),
        private_key: Some(ssi::jwk::Base64urlUInt(signing.to_bytes().to_vec())),
    }));
    let unsecured: JsonCredential = serde_json::from_value(badge()).unwrap();
    let mut options = ssi::claims::data_integrity::ProofOptions::from_method(
        ReferenceOrOwned::Reference(METHOD.parse().unwrap()),
    );
    options.created = Some("2026-11-27T00:00:00Z".parse().unwrap());
    let environment = SignatureEnvironment {
        json_ld_loader: PinnedContextLoader,
        eip712_loader: (),
    };
    let signed = AnySuite::EdDsaRdfc2022
        .sign_with(
            environment,
            unsecured,
            resolver(&public).into_vm_resolver::<AnyMethod>(),
            SingleSecretSigner::new(jwk).into_local(),
            options,
            Default::default(),
        )
        .await
        .unwrap();
    let secured = serde_json::to_value(&signed).unwrap();
    assert_eq!(secured["proof"]["cryptosuite"], "eddsa-rdfc-2022");

    let check = |document: &Value| {
        verify(
            document.to_string().as_bytes(),
            "2026-11-27T12:00:00Z",
            |method, _| {
                assert_eq!(method, METHOD);
                Ok(public)
            },
        )
        .unwrap()
    };
    assert_eq!(check(&secured), Verdict::Valid, "{secured:#}");

    let mut changed = secured.clone();
    changed["validFrom"] = "2026-10-01T00:00:00Z".into();
    assert!(matches!(check(&changed), Verdict::Invalid(_)));
}

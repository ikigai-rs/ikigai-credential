//! Verifiable credentials as ikigai resources.
//!
//! A scaffold. This crate will issue and verify W3C Verifiable Credentials 2.0 in the Open
//! Badges 3.0 profile, secured with Data Integrity `eddsa-rdfc-2022`: RDFC-1.0 canonicalization,
//! SHA-256, and an Ed25519 signature from ikigai-sign. Every name lives under [`NAMESPACE`],
//! singular and type first, partitioned by named keys (`urn:credential:id:{id}`,
//! `urn:credential:issuer:name:{i}`). The repository's README holds the planned resource map.
#![forbid(unsafe_code)]

/// The prefix every name in this module starts with.
///
/// ```
/// assert_eq!(ikigai_credential::NAMESPACE, "urn:credential:");
/// assert!("urn:credential:issuer:name:example".starts_with(ikigai_credential::NAMESPACE));
/// ```
pub const NAMESPACE: &str = "urn:credential:";

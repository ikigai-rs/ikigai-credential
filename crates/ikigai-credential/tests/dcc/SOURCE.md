# Open Badges 3.0 `AchievementCredential` JSON Schema

`ob_v3p0_achievementcredential_schema.json` is copied unmodified, byte for byte, from
<https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json>,
fetched 2026-11-27 (HTTP 200, `Last-Modified: Thu, 23 Oct 2025 12:27:25 GMT`,
`ETag: "1b896-641d28e3e0176"`, 112790 bytes). SHA-256:
`b7358e895f492e74055dc6bfc7ffc420d0e497f90c4579fb83d9519b86d393ea`. `run.mjs` checks that digest
before it serves the file, so an edited copy fails the run instead of being trusted.

It is here because DCC `verifier-core` checks an `OpenBadgeCredential` against this schema and
would otherwise fetch it. `run.mjs` answers that URL from this file, as it answers the DID
document and the pinned contexts, so the check runs with no network. Nothing in the Rust crate
reads it.

## Terms

© 1EdTech® Consortium, Inc. All Rights Reserved. Part of the 1EdTech Open Badges Specification
v3.0, <https://www.imsglobal.org/spec/ob/v3p0>. Use of the specification is governed by the
1EdTech specification license, <https://www.1edtech.org/standards/specification-license>, which
grants a royalty-free license "to download and utilize the Specification(s) for the purpose of
developing, making, having made, using … and to otherwise distribute, products that implement
this Specification(s)", requires attribution to 1EdTech, and grants no right to modify or make
derivatives. This copy is used only to test an implementation, is unmodified (the digest above),
and is attributed here. It is not part of anything this repository publishes (the crate is
`publish = false`). Trademark information: <https://www.1edtech.org/about/legal>.

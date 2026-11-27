// DCC verifier-core in both directions, offline. Usage: node run.mjs <dir>
//
// <dir> is what `cargo test --test independent_dcc -- --ignored export_for_dcc` wrote: issued.json
// (a badge ikigai-credential issued), unsigned.json, did.json (did:web:iriref.org) and
// contexts/<n>.json with contexts.json mapping each pinned context URL to its file, all from
// ikigai-jsonld's pinned copies. This script writes dcc-signed.json for the Rust side to verify.
//
// No network: globalThis.fetch is replaced BEFORE any DCC module is imported, and answers only
// the DID document and the pinned contexts from <dir>, and the Open Badges 3.0 JSON Schema
// verifier-core checks a badge against, vendored beside this script (see SOURCE.md) and checked
// against its digest. Any other URL fails the run.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, createPrivateKey, sign as edSign } from 'node:crypto';

const dir = process.argv[2];
if (!dir) throw new Error('usage: node run.mjs <dir>');
const read = (name) => JSON.parse(readFileSync(join(dir, name), 'utf8'));
const local = new Map([['https://iriref.org/.well-known/did.json', read('did.json')]]);
for (const [url, file] of Object.entries(read('contexts.json'))) local.set(url, read(file));
const OB3_SCHEMA =
  'https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json';
const OB3_SCHEMA_SHA256 = 'b7358e895f492e74055dc6bfc7ffc420d0e497f90c4579fb83d9519b86d393ea';
const schemaBytes = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ob_v3p0_achievementcredential_schema.json'),
);
const schemaDigest = createHash('sha256').update(schemaBytes).digest('hex');
if (schemaDigest !== OB3_SCHEMA_SHA256) {
  throw new Error(`the vendored OB3 schema is not the copy SOURCE.md names (sha256 ${schemaDigest})`);
}
local.set(OB3_SCHEMA, JSON.parse(schemaBytes.toString('utf8')));
const refused = [];
globalThis.fetch = async (input) => {
  const url = typeof input === 'string' ? input : input.url ?? String(input);
  const body = local.get(url.split('#')[0]);
  if (body === undefined) {
    refused.push(url);
    throw new Error(`offline: refused ${url}`);
  }
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
};

const { verifyCredential } = await import('@digitalcredentials/verifier-core');
const vc = await import('@digitalcredentials/vc');
const { DataIntegrityProof } = await import('@digitalcredentials/data-integrity');
const { cryptosuite } = await import('@digitalcredentials/eddsa-rdfc-2022-cryptosuite');
const { securityLoader } = await import('@digitalcredentials/security-document-loader');

let failed = false;
const check = (label, ok, detail) => {
  console.log(`${ok ? 'ok' : 'FAILED'}: ${label}`);
  if (!ok) {
    failed = true;
    console.log(JSON.stringify(detail, null, 2));
  }
};
const signatureValid = (result) =>
  !result.errors && result.log?.some((step) => step.id === 'valid_signature' && step.valid === true);
// verifier-core's schema verdict: one result per schema, each { schema, result: { valid } }.
const schemaResults = (result) =>
  result.additionalInformation?.find((entry) => entry.id === 'schema_check')?.results;
const schemaValid = (result) => {
  const results = schemaResults(result);
  return (
    Array.isArray(results) &&
    results.length > 0 &&
    results.every((r) => r.schema === OB3_SCHEMA && r.result?.valid === true)
  );
};
const schemaInvalid = (result) => {
  const results = schemaResults(result);
  return Array.isArray(results) && results.some((r) => r.result?.valid === false);
};

// (a) A badge issued here verifies in verifier-core; a changed claim does not.
const issued = read('issued.json');
const result = await verifyCredential({ credential: issued, knownDIDRegistries: [] });
check('verifier-core verifies the badge ikigai-credential issued', signatureValid(result), result);
const changed = structuredClone(issued);
changed.name = 'Advanced RDF';
const refusedResult = await verifyCredential({ credential: changed, knownDIDRegistries: [] });
check('verifier-core refuses it once a claim is changed', !signatureValid(refusedResult), refusedResult);
check('the badge ikigai-credential issued meets the OB3 JSON Schema, offline', schemaValid(result), result);

// (b) DCC signs the same unsigned badge with eddsa-rdfc-2022. Canonicalization, hashing and proof
// assembly are DCC's suite; only the Ed25519 primitive is Node's, from the test seed (32 bytes of
// 7, the key in did.json) as PKCS#8.
const seed = Buffer.alloc(32, 7);
const key = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
  format: 'der',
  type: 'pkcs8',
});
const signer = {
  id: 'did:web:iriref.org#key-1',
  algorithm: 'Ed25519',
  async sign({ data }) {
    return new Uint8Array(edSign(null, Buffer.from(data), key));
  },
};
const suite = new DataIntegrityProof({ signer, cryptosuite, date: '2026-11-27T00:00:00Z' });
const documentLoader = securityLoader({ fetchRemoteContexts: true }).build();
const signed = await vc.issue({ credential: read('unsigned.json'), suite, documentLoader });
writeFileSync(join(dir, 'dcc-signed.json'), JSON.stringify(signed, null, 2));
const selfCheck = await verifyCredential({ credential: signed, knownDIDRegistries: [] });
check('verifier-core verifies the badge DCC signed', signatureValid(selfCheck), selfCheck);
check('the badge DCC signed meets the OB3 JSON Schema, offline', schemaValid(selfCheck), selfCheck);

// Negative control for the schema check: verifier-core checks the schema only once the signature
// holds, so DCC signs a badge whose achievement has no description (the schema requires one).
const undescribed = read('unsigned.json');
delete undescribed.credentialSubject.achievement.description;
const undescribedSigned = await vc.issue({ credential: undescribed, suite, documentLoader });
const undescribedResult = await verifyCredential({ credential: undescribedSigned, knownDIDRegistries: [] });
check(
  'the OB3 JSON Schema refuses a signed badge whose achievement has no description',
  signatureValid(undescribedResult) && schemaInvalid(undescribedResult),
  undescribedResult,
);

check('nothing was fetched from the network', refused.length === 0, refused);
process.exit(failed ? 1 : 0);

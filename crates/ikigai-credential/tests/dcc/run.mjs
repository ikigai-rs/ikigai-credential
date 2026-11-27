// DCC verifier-core in both directions, offline. Usage: node run.mjs <dir>
//
// <dir> is what `cargo test --test independent_dcc -- --ignored export_for_dcc` wrote: issued.json
// (a badge ikigai-credential issued), unsigned.json, did.json (did:web:iriref.org) and
// contexts/<n>.json with contexts.json mapping each pinned context URL to its file, all from
// ikigai-jsonld's pinned copies. This script writes dcc-signed.json for the Rust side to verify.
//
// No network: globalThis.fetch is replaced BEFORE any DCC module is imported, and answers only
// the DID document and the pinned contexts from <dir>; any other URL fails the run.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createPrivateKey, sign as edSign } from 'node:crypto';

const dir = process.argv[2];
if (!dir) throw new Error('usage: node run.mjs <dir>');
const read = (name) => JSON.parse(readFileSync(join(dir, name), 'utf8'));
const local = new Map([['https://iriref.org/.well-known/did.json', read('did.json')]]);
for (const [url, file] of Object.entries(read('contexts.json'))) local.set(url, read(file));
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

// (a) A badge issued here verifies in verifier-core; a changed claim does not.
const issued = read('issued.json');
const result = await verifyCredential({ credential: issued, knownDIDRegistries: [] });
check('verifier-core verifies the badge ikigai-credential issued', signatureValid(result), result);
const changed = structuredClone(issued);
changed.name = 'Advanced RDF';
const refusedResult = await verifyCredential({ credential: changed, knownDIDRegistries: [] });
check('verifier-core refuses it once a claim is changed', !signatureValid(refusedResult), refusedResult);

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

check('nothing was fetched from the network', refused.length === 0, refused);
process.exit(failed ? 1 : 0);

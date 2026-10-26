// R4-M37-P vector generator. Independent of the Dart implementation:
// X25519, HKDF-SHA-256, HMAC-SHA-256, SHA-256 and AES-256-GCM come from
// Node's OpenSSL-backed `crypto`; ML-KEM-768 comes from the OpenSSL 3.6 CLI.
// The byte layouts are re-derived here from the contract (§2, §3) and the
// spec written in the result file, never from the Dart sources.
//
// Usage: node gen.js <workdir> <out.json> [<previous.json>]
// ML-KEM encapsulation is randomized. With <previous.json>, its ciphertexts
// and the relay's ground key are reused and re-checked (OpenSSL decapsulation,
// the SAS collision), so every earlier field is reproduced byte for byte.
'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const OPENSSL = '/opt/homebrew/bin/openssl';
const work = process.argv[2];
const out = process.argv[3];
const previous = process.argv[4] ? JSON.parse(fs.readFileSync(process.argv[4], 'utf8')).handshake : null;

const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const lp = (x) => Buffer.concat([u32(x.length), x]);
const asBuf = (x) => (Buffer.isBuffer(x) ? x : Buffer.from(x, 'utf8'));
// `a || b || ...` in the contract: every operand length-prefixed.
const cat = (...parts) => Buffer.concat(parts.map((p) => lp(asBuf(p))));
const hex = (b) => Buffer.from(b).toString('hex');
const b64url = (b) => Buffer.from(b).toString('base64url');
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const hmac = (k, d) => crypto.createHmac('sha256', k).update(d).digest();
// RFC 5869 with L = 32 (one block). Written out because OpenSSL 3.0's HKDF
// (behind crypto.hkdfSync) refuses an info longer than 1024 bytes, and the
// contract's info carries the whole transcript (kO.pub alone is 1184 bytes).
// Cross-checked against crypto.hkdfSync below wherever the info is short.
const hkdf = (ikm, salt, info) => {
  const prk = hmac(salt, ikm);
  return hmac(prk, Buffer.concat([info, Buffer.from([1])]));
};
{
  const ikm = Buffer.from('cross-check ikm');
  const salt = Buffer.from('cross-check salt');
  const info = Buffer.from('cross-check info');
  const ref = Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, 32));
  if (!hkdf(ikm, salt, info).equals(ref)) throw new Error('manual HKDF mismatch');
  const zeroSalt = Buffer.alloc(32);
  const ref2 = Buffer.from(crypto.hkdfSync('sha256', ikm, zeroSalt, info, 32));
  if (!hkdf(ikm, zeroSalt, info).equals(ref2)) throw new Error('manual HKDF mismatch 2');
}

// ── fixed synthetic inputs ─────────────────────────────────────────────
const seed = (label) => sha256(Buffer.from('r4-m37 vector ' + label));
const s = seed('s');
const eOPriv = seed('eO');
const eNPriv = seed('eN');
const kOSeed = crypto.createHash('sha512').update('r4-m37 vector kO').digest();
const apiHost = 'api.example.test';

// ── X25519 (Node) ──────────────────────────────────────────────────────
const PKCS8_X25519 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const x25519Priv = (raw) =>
  crypto.createPrivateKey({ key: Buffer.concat([PKCS8_X25519, raw]), format: 'der', type: 'pkcs8' });
const x25519Pub = (priv) =>
  crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32);
const x25519PubKey = (raw) =>
  crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), raw]), format: 'der', type: 'spki' });
const eO = x25519Priv(eOPriv);
const eN = x25519Priv(eNPriv);
const eOPub = Buffer.from(x25519Pub(eO));
const eNPub = Buffer.from(x25519Pub(eN));
const dhN = crypto.diffieHellman({ privateKey: eN, publicKey: x25519PubKey(eOPub) });
const dhO = crypto.diffieHellman({ privateKey: eO, publicKey: x25519PubKey(eNPub) });
if (!dhN.equals(dhO)) throw new Error('X25519 disagreement');

// ── ML-KEM-768 (OpenSSL CLI) ───────────────────────────────────────────
const p = (n) => path.join(work, n);
execFileSync(OPENSSL, ['genpkey', '-algorithm', 'ML-KEM-768', '-pkeyopt', 'hexseed:' + hex(kOSeed), '-out', p('kO.pem')]);
const text = execFileSync(OPENSSL, ['pkey', '-in', p('kO.pem'), '-text', '-noout']).toString();
const field = (name) => {
  const m = text.match(new RegExp('^' + name + ':\\n((?:\\s+[0-9a-f:]+\\n)+)', 'm'));
  return Buffer.from(m[1].replace(/[\s:]/g, ''), 'hex');
};
const kODk = field('dk');
const kOEk = field('ek');
if (kODk.length !== 2400 || kOEk.length !== 1184) throw new Error('ML-KEM sizes');
execFileSync(OPENSSL, ['pkey', '-in', p('kO.pem'), '-pubout', '-outform', 'DER', '-out', p('kO.pub.der')]);
// One encapsulation to kO.pub: fresh, or the previous run's ciphertext; either
// way OpenSSL must decapsulate it to the recorded secret.
const encapsulate = (name, priorCtHex, priorSsHex) => {
  if (priorCtHex) {
    fs.writeFileSync(p(name + '-ct.bin'), Buffer.from(priorCtHex, 'hex'));
    fs.writeFileSync(p(name + '-ss.bin'), Buffer.from(priorSsHex, 'hex'));
  } else {
    execFileSync(OPENSSL, ['pkeyutl', '-encap', '-inkey', p('kO.pub.der'), '-pubin', '-keyform', 'DER', '-secret', p(name + '-ss.bin'), '-out', p(name + '-ct.bin')]);
  }
  const ct = fs.readFileSync(p(name + '-ct.bin'));
  const ss = fs.readFileSync(p(name + '-ss.bin'));
  execFileSync(OPENSSL, ['pkeyutl', '-decap', '-inkey', p('kO.pem'), '-in', p(name + '-ct.bin'), '-secret', p(name + '-ss2.bin')]);
  if (!fs.readFileSync(p(name + '-ss2.bin')).equals(ss) || ct.length !== 1088) throw new Error('ML-KEM decap ' + name);
  return { ct, ss };
};
const { ct, ss: ssKem } = encapsulate('n', previous && previous.kemCiphertextHex, previous && previous.kemSharedSecretHex);

// ── handshake ──────────────────────────────────────────────────────────
const slot = sha256(cat('risaal-xfer-slot-v1', s));
const transcript = cat(eOPub, kOEk, eNPub, ct);
const deriveK = (salt) => hkdf(cat(dhN, ssKem), salt, cat('risaal-xfer-v1', transcript));
const K = deriveK(s);
const zeros = Buffer.alloc(32);
const sub = (k, label) => hkdf(k, zeros, cat(label));
const kMac = sub(K, 'risaal-xfer-mac-v1');
const kEnc = sub(K, 'risaal-xfer-enc-v1');
const sasBytes = sub(K, 'risaal-xfer-sas-v1');
const getTag = hmac(kMac, cat('get', transcript));
const completeTag = hmac(kMac, cat('complete', transcript));
const joinMac = hmac(kMac, cat('join', transcript, getTag, completeTag));
// Key confirmation O -> N (contract §2f): N shows its code only after this
// verifies under its own K.
const confirmTag = hmac(kMac, cat('confirm', transcript));

const SAS_LIMIT = 4294000000; // floor(2^32 / 10^6) * 10^6
const sasFrom = (bytes) => {
  for (let i = 0; i + 4 <= bytes.length; i += 4) {
    const w = bytes.readUInt32BE(i);
    if (w < SAS_LIMIT) return String(w % 1000000).padStart(6, '0');
  }
  return null;
};
const sas = sasFrom(sasBytes);

const wrongS = Buffer.from(s); wrongS[31] ^= 0x01;
const kWrong = deriveK(wrongS);
const sasWrong = sasFrom(sub(kWrong, 'risaal-xfer-sas-v1'));
const kMacWrong = sub(kWrong, 'risaal-xfer-mac-v1');
const getTagWrong = hmac(kMacWrong, cat('get', transcript));
const completeTagWrong = hmac(kMacWrong, cat('complete', transcript));
const joinMacWrong = hmac(kMacWrong, cat('join', transcript, getTagWrong, completeTagWrong));
const confirmTagWrong = hmac(kMacWrong, cat('confirm', transcript));

// ── relay substitution (M37-CRYPTO-1) ──────────────────────────────────
// A malicious relay that holds a photo of the QR (s, eO.pub, kO.pub) withholds
// N's join and grinds its own (eN', ct') until O's code equals N's: about
// 1e6 tries. O accepts that join, but O's confirmTag is then under K' != K,
// so N must refuse it and never show a code.
const prior = previous && previous.relayJoin;
const relayKem = encapsulate('relay', prior && prior.kemCiphertextHex, prior && prior.kemSharedSecretHex);
const relayFrom = (priv) => {
  const pub = Buffer.from(x25519Pub(priv));
  const dh = crypto.diffieHellman({ privateKey: priv, publicKey: x25519PubKey(eOPub) });
  const tr = cat(eOPub, kOEk, pub, relayKem.ct);
  const k = hkdf(cat(dh, relayKem.ss), s, cat('risaal-xfer-v1', tr));
  return { pub, dh, tr, k, sas: sasFrom(sub(k, 'risaal-xfer-sas-v1')) };
};
let relayPriv = prior ? Buffer.from(prior.newX25519PrivateHex, 'hex') : null;
let relayTries = prior ? prior.grindTries : 0;
while (!relayPriv) {
  relayTries++;
  const candidate = crypto.generateKeyPairSync('x25519').privateKey;
  if (relayFrom(candidate).sas === sas) {
    relayPriv = candidate.export({ format: 'der', type: 'pkcs8' }).subarray(-32);
  }
}
const relay = relayFrom(x25519Priv(relayPriv));
const relayKMac = sub(relay.k, 'risaal-xfer-mac-v1');
const relayGetTag = hmac(relayKMac, cat('get', relay.tr));
const relayCompleteTag = hmac(relayKMac, cat('complete', relay.tr));
const relayJoinMac = hmac(relayKMac, cat('join', relay.tr, relayGetTag, relayCompleteTag));
const relayConfirmTag = hmac(relayKMac, cat('confirm', relay.tr));
if (relay.sas !== sas || relay.k.equals(K) || relayConfirmTag.equals(confirmTag)) {
  throw new Error('relay vector: want the same code under a different K');
}

const qrBytes = Buffer.concat([Buffer.from([1]), lp(s), lp(eOPub), lp(kOEk), lp(Buffer.from(apiHost))]);
const qr = 'rx1:' + b64url(qrBytes);

// ── archive v1 ─────────────────────────────────────────────────────────
const KIND = { crypto_store: 1, kt: 2, profile_own: 3, peer_profiles: 4, contacts_cache: 5, conversations_cache: 6, group_roster: 7, prefs: 8, history: 9 };
const entries = [
  ['prefs', 'theme', 'dark'],
  ['crypto_store', 'crypto_identity_key_pair', '{"pk":"AA=="}'],
  ['kt', 'crypto_kt_head_v1', '{"h":1}'],
  ['crypto_store', 'crypto_e2_protocol', 'risaal-e2ee-2'],
].map(([k, key, v]) => ({ kind: KIND[k], kindName: k, key: Buffer.from(key), value: Buffer.from(v) }));
entries.sort((a, b) => (a.kind - b.kind) || Buffer.compare(a.key, b.key));
const archive = Buffer.concat([
  Buffer.from('RXA'), Buffer.from([1]), u32(entries.length),
  ...entries.map((e) => Buffer.concat([Buffer.from([e.kind]), u16(e.key.length), e.key, u32(e.value.length), e.value])),
]);
const chunkBytes = 96;
const total = Math.ceil(archive.length / chunkBytes);
if (total !== 2) throw new Error('want a two-chunk archive, got ' + total);
const chunks = [];
for (let i = 0; i < total; i++) {
  const pt = archive.subarray(i * chunkBytes, Math.min(archive.length, (i + 1) * chunkBytes));
  const nonce = Buffer.concat([Buffer.alloc(4), u64(i)]);
  const aad = cat(slot, u32(i), u32(total));
  const c = crypto.createCipheriv('aes-256-gcm', kEnc, nonce);
  c.setAAD(aad);
  const body = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
  chunks.push({ index: i, nonceHex: hex(nonce), aadHex: hex(aad), chunkHex: hex(body) });
}

const doc = {
  description:
    'R4-M37 device transfer vectors (contracts/R4-M37-DEVICE-TRANSFER.md §2-§3, results/R4-M37-P.md). ' +
    'Synthetic keys only. Generated by an independent Node.js script (OpenSSL-backed crypto: X25519, HKDF-SHA-256, ' +
    'HMAC-SHA-256, SHA-256, AES-256-GCM) and the OpenSSL 3.6 CLI (ML-KEM-768 keygen from seed, encapsulation, ' +
    'decapsulation cross-check), never from the Dart implementation.',
  handshake: {
    secretHex: hex(s),
    oldX25519PrivateHex: hex(eOPriv),
    oldX25519PublicHex: hex(eOPub),
    oldKemSeedHex: hex(kOSeed),
    oldKemPublicHex: hex(kOEk),
    oldKemSecretHex: hex(kODk),
    newX25519PrivateHex: hex(eNPriv),
    newX25519PublicHex: hex(eNPub),
    kemCiphertextHex: hex(ct),
    kemSharedSecretHex: hex(ssKem),
    x25519SharedHex: hex(dhN),
    apiHost,
    slotHex: hex(slot),
    transcriptSha256Hex: hex(sha256(transcript)),
    kHex: hex(K),
    kMacHex: hex(kMac),
    kEncHex: hex(kEnc),
    sasBytesHex: hex(sasBytes),
    sas,
    getTagHex: hex(getTag),
    completeTagHex: hex(completeTag),
    joinMacHex: hex(joinMac),
    confirmTagHex: hex(confirmTag),
    joinBody: { eN: b64url(eNPub), ct: b64url(ct), getTag: b64url(getTag), completeTag: b64url(completeTag), mac: b64url(joinMac) },
    wrongSecret: { secretHex: hex(wrongS), kHex: hex(kWrong), sas: sasWrong, joinMacHex: hex(joinMacWrong), confirmTagHex: hex(confirmTagWrong) },
    relayJoin: {
      description:
        'M37-CRYPTO-1: the join a relay holding the QR substitutes for N\'s, ground until its SAS equals the SAS above ' +
        '(same 6 digits, different K). O accepts it; N must refuse its confirmTag.',
      grindTries: relayTries,
      newX25519PrivateHex: hex(relayPriv),
      newX25519PublicHex: hex(relay.pub),
      kemCiphertextHex: hex(relayKem.ct),
      kemSharedSecretHex: hex(relayKem.ss),
      x25519SharedHex: hex(relay.dh),
      kHex: hex(relay.k),
      sas: relay.sas,
      confirmTagHex: hex(relayConfirmTag),
      joinBody: { eN: b64url(relay.pub), ct: b64url(relayKem.ct), getTag: b64url(relayGetTag), completeTag: b64url(relayCompleteTag), mac: b64url(relayJoinMac) },
    },
  },
  qr: { qrBytesHex: hex(qrBytes), qr },
  sas: {
    limit: SAS_LIMIT,
    cases: [
      { bytesHex: 'fffffffffff13d80fff13d7f' + '00'.repeat(20), sas: '999999' },
      { bytesHex: '000f4240' + 'ff'.repeat(28), sas: '000000' },
      { bytesHex: '0001e240' + '00'.repeat(28), sas: '123456' },
      { bytesHex: 'ff'.repeat(32), sas: null },
    ].map((c) => {
      const got = sasFrom(Buffer.from(c.bytesHex, 'hex'));
      if (got !== c.sas) throw new Error('sas case ' + c.bytesHex + ' -> ' + got);
      return c;
    }),
  },
  archive: {
    entries: entries.map((e) => ({ kind: e.kindName, kindId: e.kind, key: e.key.toString(), valueHex: hex(e.value) })),
    archiveHex: hex(archive),
    chunkBytes,
    total,
    chunks,
  },
};
fs.writeFileSync(out, JSON.stringify(doc, null, 2) + '\n');
console.log('ok', { sas, sasWrong, relaySas: relay.sas, relayTries, total, archiveLen: archive.length, qrLen: qr.length });

// Secret-free verifier. This module never signs, reads credentials, or uses a network.
// Protocol provenance (exact upstream tags):
// https://github.com/jedisct1/rust-minisign-verify/blob/0.2.5/src/lib.rs
// https://github.com/tauri-apps/plugins-workspace/blob/updater-v2.13.2/plugins/updater/src/updater.rs
// Ed = Ed25519(artifact); ED = Ed25519(BLAKE2b-512(artifact)). In BOTH modes
// the global Ed25519 signature covers signature[64] || UTF8(trusted comment),
// excluding the "trusted comment: " prefix. This is NOT RFC 8032 Ed25519ph.
// Like Tauri 2.13.2 we verify both signatures before trusting version metadata.
// Our release policy is deliberately stricter: bounded canonical envelopes and
// exactly one tab-delimited version field, with canonical stable three-part semver.

import {createHash, createPublicKey, verify as verifyEd25519} from 'node:crypto';
import {constants, openSync, closeSync, fstatSync, lstatSync, readSync} from 'node:fs';
import {pathToFileURL} from 'node:url';

export const LIMITS = Object.freeze({
  artifactBytes: 256 * 1024 * 1024,
  signatureBytes: 16384,
  signatureTextBytes: 12288,
  publicKeyBytes: 2048,
  publicKeyTextBytes: 1024,
  commentBytes: 4096,
  versionBytes: 62,
});
export const PINNED_PUBLIC_KEY_PACKET_SHA256 =
  '58ac84cd7ad44dd4b5c1002551deb3693b8a792d2f409bc1121c0e6bf864e16c';
const PUBLIC_KEY_FILE = new URL('../updater-public-key.pub', import.meta.url);
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function fail(message) { throw new Error(message); }
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

function boundedText(value, limit, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > limit ||
      Buffer.byteLength(value, 'utf8') > limit) fail(`Invalid or oversized ${label}`);
  return value;
}

function base64(value, maxBytes, label) {
  if (!value || value.length > Math.ceil(maxBytes / 3) * 4 ||
      value.length % 4 !== 0 || !BASE64.test(value)) fail(`Invalid ${label} base64`);
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length > maxBytes || bytes.toString('base64') !== value) {
    fail(`Non-canonical or oversized ${label} base64`);
  }
  return bytes;
}

function utf8(bytes, label) {
  const value = bytes.toString('utf8');
  if (!Buffer.from(value, 'utf8').equals(bytes)) fail(`Invalid ${label} UTF-8`);
  return value;
}

function envelope(value, inputLimit, decodedLimit, label) {
  boundedText(value, inputLimit, label);
  // Permit one normal file terminator, not arbitrary whitespace or blank lines.
  const canonical = value.replace(/\r?\n$/, '');
  return {canonical, text: utf8(base64(canonical, decodedLimit, label), label)};
}

function lines(text, count, label) {
  const result = text.split(/\r?\n/);
  if (result.at(-1) === '') result.pop();
  if (result.length !== count || result.some(line => line.includes('\r'))) {
    fail(`Invalid ${label} line structure`);
  }
  return result;
}

function comment(value, prefix, label) {
  boundedText(value, LIMITS.commentBytes, label);
  if (!value.startsWith(prefix) || /[\x00-\x08\x0a-\x1f\x7f]/.test(value)) {
    fail(`Invalid ${label}`);
  }
  return value.slice(prefix.length);
}

export function validateStableVersion(version) {
  boundedText(version, LIMITS.versionBytes, 'stable version');
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(version);
  // JavaScript's $ also matches before a final newline; require the entire input.
  if (!match || match[0] !== version ||
      version.split('.').some(part => BigInt(part) > 0xffffffffffffffffn)) {
    fail('Expected canonical stable three-part version');
  }
  return version;
}

function parsePublicKey(publicKey) {
  const {canonical, text} = envelope(publicKey, LIMITS.publicKeyBytes,
    LIMITS.publicKeyTextBytes, 'Tauri public key');
  const [header, body] = lines(text, 2, 'public key');
  const match = /^untrusted comment: minisign public key:? ([0-9A-F]{16})$/.exec(header);
  if (!match) fail('Expected minisign public-key comment');
  const packet = base64(body, 42, 'public-key packet');
  if (packet.length !== 42 || !packet.subarray(0, 2).equals(Buffer.from('Ed'))) {
    fail('Expected 42-byte Ed25519 public-key packet');
  }
  const keyId = packet.readBigUInt64LE(2).toString(16).padStart(16, '0').toUpperCase();
  if (keyId !== match[1]) fail('Public-key comment and packet key ID disagree');
  return {
    canonical, keyId, keyIdBytes: packet.subarray(2, 10), packetSha256: sha256(packet),
    key: createPublicKey({key: Buffer.concat([ED25519_SPKI_PREFIX, packet.subarray(10)]),
      format: 'der', type: 'spki'}),
  };
}

function parseSignature(signature) {
  const {canonical, text} = envelope(signature, LIMITS.signatureBytes,
    LIMITS.signatureTextBytes, 'Tauri signature');
  const [header, body, trustedLine, globalLine] = lines(text, 4, 'signature');
  comment(header, 'untrusted comment: ', 'untrusted comment');
  const trustedComment = comment(trustedLine, 'trusted comment: ', 'trusted comment');
  const packet = base64(body, 74, 'signature packet');
  const globalSignature = base64(globalLine, 64, 'global signature');
  if (packet.length !== 74 || globalSignature.length !== 64) fail('Invalid signature packet length');
  const algorithm = packet.subarray(0, 2).toString('latin1');
  if (algorithm !== 'Ed' && algorithm !== 'ED') fail('Unsupported minisign signature algorithm');
  return {canonical, algorithm, keyIdBytes: packet.subarray(2, 10),
    signatureBytes: packet.subarray(10), globalSignature, trustedComment};
}

function artifactLimit(limit) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > LIMITS.artifactBytes) {
    fail('Artifact size limit must be a positive integer within the hard cap');
  }
  return limit;
}

/** Generic, pure verifier for explicitly supplied public keys; production uses the pinned wrapper. */
export function verifySignature({artifactBytes, signature, publicKey, expectedVersion,
  maxArtifactBytes = LIMITS.artifactBytes} = {}) {
  validateStableVersion(expectedVersion);
  const limit = artifactLimit(maxArtifactBytes);
  if (!(artifactBytes instanceof Uint8Array) || artifactBytes.byteLength === 0 ||
      artifactBytes.byteLength > limit) fail('Invalid or oversized artifact bytes');
  // Own a snapshot so a caller cannot mutate an input while it is being verified.
  const bytes = Buffer.from(artifactBytes);
  const key = parsePublicKey(publicKey);
  const parsed = parseSignature(signature);
  if (!key.keyIdBytes.equals(parsed.keyIdBytes)) fail('Signature key ID does not match public key');
  const message = parsed.algorithm === 'ED' ? createHash('blake2b512').update(bytes).digest() : bytes;
  if (!verifyEd25519(null, message, key.key, parsed.signatureBytes)) {
    fail('Artifact signature verification failed');
  }
  const globalMessage = Buffer.concat([parsed.signatureBytes, Buffer.from(parsed.trustedComment, 'utf8')]);
  if (!verifyEd25519(null, globalMessage, key.key, parsed.globalSignature)) {
    fail('Trusted-comment global signature verification failed');
  }
  // No version extraction or interpretation until BOTH cryptographic checks succeeded.
  const versions = parsed.trustedComment.split('\t').filter(field => field.startsWith('version:'));
  if (versions.length !== 1) fail('Expected exactly one signed version field');
  const version = validateStableVersion(versions[0].slice('version:'.length));
  if (version !== expectedVersion) fail('Signed version does not match expected release version');
  return Object.freeze({algorithm: parsed.algorithm, keyId: key.keyId, version,
    artifactSize: bytes.length, artifactSha256: sha256(bytes),
    publicKeyPacketSha256: key.packetSha256, signature: parsed.canonical});
}

/** Read at most cap bytes from one regular-file handle; reject truncation/growth during reading. */
export function readBoundedFile(path, cap, label = 'input') {
  if (!Number.isSafeInteger(cap) || cap < 1 || cap > LIMITS.artifactBytes) fail('Invalid read size limit');
  const entry = lstatSync(path);
  if (!entry.isFile() || entry.isSymbolicLink()) fail(`Expected regular ${label} file`);
  // Nonblocking/no-follow where supported: a path race must not turn a bounded
  // file read into a blocking FIFO read or a symlink to an unrelated file.
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK || 0) | (constants.O_NOFOLLOW || 0));
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.size === 0 || before.size > cap) fail(`Invalid or oversized ${label} file`);
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, null);
      if (count === 0) fail(`${label} file changed during verification`);
      offset += count;
    }
    const extra = readSync(fd, Buffer.alloc(1), 0, 1, null);
    const after = fstatSync(fd);
    if (extra || before.size !== after.size || before.mtimeMs !== after.mtimeMs ||
        before.ctimeMs !== after.ctimeMs) fail(`${label} file changed during verification`);
    return bytes;
  } finally { closeSync(fd); }
}

/** Production path: no key override, environment credential, or network lookup. */
export function verifySignatureFile({artifactPath, signaturePath, expectedVersion,
  maxArtifactBytes = LIMITS.artifactBytes} = {}) {
  validateStableVersion(expectedVersion);
  const publicKey = utf8(readBoundedFile(PUBLIC_KEY_FILE, LIMITS.publicKeyBytes, 'public key'), 'public key');
  if (parsePublicKey(publicKey).packetSha256 !== PINNED_PUBLIC_KEY_PACKET_SHA256) {
    fail('Checked-in public key does not match the pinned release key');
  }
  const signature = utf8(readBoundedFile(signaturePath, LIMITS.signatureBytes, 'signature'), 'signature');
  const artifactBytes = readBoundedFile(artifactPath, artifactLimit(maxArtifactBytes), 'artifact');
  return verifySignature({artifactBytes, signature, publicKey, expectedVersion, maxArtifactBytes});
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [artifactPath, signaturePath, expectedVersion, ...extra] = process.argv.slice(2);
    if (!artifactPath || !signaturePath || !expectedVersion || extra.length) {
      fail('Usage: node release/pipeline/verify-signature.mjs ARTIFACT SIGNATURE_FILE VERSION');
    }
    const {signature: _, ...result} = verifySignatureFile({artifactPath, signaturePath, expectedVersion});
    process.stdout.write(JSON.stringify(result) + '\n');
  } catch (error) {
    process.stderr.write(`Signature verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

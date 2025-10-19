const crypto = require('crypto');

/**
 * canonicalize JSON payload
 */
function canonicalizePayload(payload) {
  return JSON.stringify(payload, Object.keys(payload).sort());
}

/**
 * generating content_sig for Direct Message
 */
function generateContentSigDM(ciphertext, from, to, ts, rsaCrypto, privateKey) {
  const message = `${ciphertext}||${from}||${to}||${ts}`;
  const hash = crypto.createHash('sha256').update(message).digest();
  return rsaCrypto.sign(hash, privateKey);
}

/**
 * verify content_sig for Direct Message
 */
function verifyContentSigDM(ciphertext, from, to, ts, contentSig, rsaCrypto, publicKey) {
  const message = `${ciphertext}||${from}||${to}||${ts}`;
  const hash = crypto.createHash('sha256').update(message).digest();
  return rsaCrypto.verify(hash, contentSig, publicKey);
}

/**
 * Generating content_sig for Public Channel
 */
function generateContentSigPublic(ciphertext, from, ts, rsaCrypto, privateKey) {
  const message = `${ciphertext}||${from}||${ts}`;
  const hash = crypto.createHash('sha256').update(message).digest();
  return rsaCrypto.sign(hash, privateKey);
}

/**
 * verifing content_sig for Public Channel
 */
function verifyContentSigPublic(ciphertext, from, ts, contentSig, rsaCrypto, publicKey) {
  const message = `${ciphertext}||${from}||${ts}`;
  const hash = crypto.createHash('sha256').update(message).digest();
  return rsaCrypto.verify(hash, contentSig, publicKey);
}

/**
 * Generates transport signature for envelope
 */
function signEnvelope(payload, rsaCrypto, privateKey) {
  const canonical = canonicalizePayload(payload);
  return rsaCrypto.sign(canonical, privateKey);
}

/**
 * verifing transport signature for envelope
 */
function verifyEnvelope(payload, signature, rsaCrypto, publicKey) {
  const canonical = canonicalizePayload(payload);
  return rsaCrypto.verify(canonical, signature, publicKey);
}

module.exports = {
  canonicalizePayload,
  generateContentSigDM,
  verifyContentSigDM,
  generateContentSigPublic,
  verifyContentSigPublic,
  signEnvelope,
  verifyEnvelope
};
/**
 * Encryption at rest for the one column that holds captured content.
 *
 * WHY THIS EXISTS
 * `EVIDENCE_ENCRYPTION_KEY` has been in `.env.example` since the beginning,
 * and the architecture document stated that evidence was "stored as Bytes
 * with an encryption key configured separately". Nothing read the key. The
 * column held plain UTF-8, and a config variable that promises encryption
 * while doing nothing is worse than no variable at all -- it is the kind of
 * claim somebody relies on without checking.
 *
 * WHAT IS ACTUALLY IN THERE
 * Filenames, window titles, and the classifier's already-masked samples
 * (`****-****-****-4242`) -- never a raw card number; see
 * `agent/src/evidence.py` for why that guarantee holds upstream. So this is
 * defence in depth over data that is already redacted, not the only thing
 * standing between a database dump and a PCI finding. It is worth having
 * anyway: filenames alone tell an attacker which files are worth going after.
 *
 * FORMAT
 *     [0x01][12-byte IV][16-byte GCM tag][ciphertext]
 *
 * AES-256-GCM, a fresh random IV per row. The version byte both identifies
 * the scheme and distinguishes a sealed value from a legacy plaintext row:
 * evidence is human-readable text, so byte 0x01 cannot begin one. Rows
 * written before this existed still read correctly, and are re-sealed the
 * next time they are written rather than migrated in a batch -- a migration
 * that has to decrypt every row to succeed is a migration that can fail
 * halfway.
 *
 * NO KEY CONFIGURED
 * Falls back to plaintext, exactly as before, with one warning at startup.
 * A backend that refuses to record incidents because an optional key is
 * missing turns a configuration gap into a detection outage.
 */

const crypto = require('crypto');

const VERSION = 0x01;
const IV_BYTES = 12;
const TAG_BYTES = 16;

let warned = false;

/**
 * The 32-byte key, or null when none is configured.
 *
 * Read on every call rather than cached at module load: the test suite sets
 * the environment in `setupEnv.js`, and a key captured at import time would
 * depend on which file required this module first.
 */
function key() {
  const raw = process.env.EVIDENCE_ENCRYPTION_KEY;
  if (!raw) return null;
  // A passphrase of any length becomes a 32-byte key. Hashing rather than
  // padding, so a short key is not silently weaker than it looks -- and so
  // the documented "32-char key" and a longer one both work.
  return crypto.createHash('sha256').update(String(raw)).digest();
}

function warnOnce() {
  if (warned) return;
  warned = true;
  console.warn(
    '[evidence] EVIDENCE_ENCRYPTION_KEY is not set -- incident evidence will '
    + 'be stored as plaintext. Set it to encrypt at rest.',
  );
}

/** Encrypt text for storage. Returns a Buffer ready for the Bytes column. */
function seal(text) {
  const plain = Buffer.from(String(text), 'utf8');
  const k = key();
  if (!k) {
    warnOnce();
    return plain;
  }
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', k, iv);
  const body = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([Buffer.from([VERSION]), iv, cipher.getAuthTag(), body]);
}

/**
 * Decrypt a stored value back to text.
 *
 * Never throws. A row that cannot be decrypted -- written under a key that
 * has since changed, or truncated -- returns a marker rather than taking the
 * whole incidents page down with it: one unreadable evidence field must not
 * cost an analyst the other two hundred rows in the queue.
 */
function open(buf) {
  if (buf === null || buf === undefined) return null;
  const bytes = Buffer.from(buf);
  if (bytes.length === 0) return '';

  // Legacy plaintext, or a value written while no key was configured.
  if (bytes[0] !== VERSION) return bytes.toString('utf8');
  if (bytes.length < 1 + IV_BYTES + TAG_BYTES) return bytes.toString('utf8');

  const k = key();
  if (!k) return '[evidence encrypted -- EVIDENCE_ENCRYPTION_KEY not set]';

  try {
    const iv = bytes.subarray(1, 1 + IV_BYTES);
    const tag = bytes.subarray(1 + IV_BYTES, 1 + IV_BYTES + TAG_BYTES);
    const body = bytes.subarray(1 + IV_BYTES + TAG_BYTES);
    const decipher = crypto.createDecipheriv('aes-256-gcm', k, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
  } catch {
    return '[evidence could not be decrypted]';
  }
}

/** Is encryption actually on? Used by the health/readiness surface. */
function enabled() {
  return key() !== null;
}

module.exports = { seal, open, enabled, VERSION };

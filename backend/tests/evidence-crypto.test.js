const { seal, open, enabled, VERSION } = require('../src/lib/evidence-crypto');

const KEY = process.env.EVIDENCE_ENCRYPTION_KEY;

afterEach(() => { process.env.EVIDENCE_ENCRYPTION_KEY = KEY; });

describe('evidence at rest', () => {
  test('a sealed value comes back as what went in', () => {
    const text = 'customers.csv [copied to removable E:\\ -- removed]';
    expect(open(seal(text))).toBe(text);
  });

  test('the stored bytes are not the plaintext', () => {
    // The whole point: a database dump should not hand over filenames.
    const text = 'quarterly_customer_cards.csv';
    const sealed = seal(text);
    expect(sealed.includes(Buffer.from(text))).toBe(false);
    expect(sealed[0]).toBe(VERSION);
  });

  test('two seals of the same text differ', () => {
    // A fresh IV per row, so identical evidence does not produce identical
    // ciphertext and reveal which incidents are about the same file.
    expect(seal('cards.csv').equals(seal('cards.csv'))).toBe(false);
  });

  test('unicode survives the round trip', () => {
    const text = 'rapport_privé.xlsx — données clients';
    expect(open(seal(text))).toBe(text);
  });

  test('a row written before encryption existed still reads', () => {
    // Plaintext rows are not migrated in a batch: a migration that must
    // decrypt every row to succeed is one that can fail halfway.
    const legacy = Buffer.from('old-incident.csv', 'utf8');
    expect(open(legacy)).toBe('old-incident.csv');
  });

  test('null and empty are passed through, not sealed into something', () => {
    expect(open(null)).toBeNull();
    expect(open(Buffer.alloc(0))).toBe('');
  });

  test('a value sealed under a different key does not throw', () => {
    // One unreadable field must not cost an analyst the other 200 rows.
    const sealed = seal('cards.csv');
    process.env.EVIDENCE_ENCRYPTION_KEY = 'a-completely-different-key-value';
    expect(open(sealed)).toBe('[evidence could not be decrypted]');
  });

  test('a truncated row does not throw', () => {
    const sealed = seal('cards.csv');
    expect(() => open(sealed.subarray(0, 10))).not.toThrow();
  });

  test('with no key configured it stores plaintext rather than refusing', () => {
    // A backend that will not record incidents because an optional key is
    // missing turns a config gap into a detection outage.
    delete process.env.EVIDENCE_ENCRYPTION_KEY;
    expect(enabled()).toBe(false);
    const sealed = seal('cards.csv');
    expect(sealed.toString('utf8')).toBe('cards.csv');
    expect(open(sealed)).toBe('cards.csv');
  });

  test('the key is read per call, not captured at import', () => {
    // setupEnv.js sets the environment after modules load, so a cached key
    // would depend on which test file required this one first.
    expect(enabled()).toBe(true);
    delete process.env.EVIDENCE_ENCRYPTION_KEY;
    expect(enabled()).toBe(false);
  });
});

const { aes } = require('..');

// OpenSSL evpciph_aes_common.txt, AES-256-GCM, zero key and 96-bit zero IV.
// https://github.com/openssl/openssl/blob/master/test/recipes/30-test_evp_data/evpciph_aes_common.txt
// Each fixture is an independent known-answer test with empty associated data.
describe('OpenSSL AES-256-GCM vectors', () => {
    const key = '\0'.repeat(32);
    const nonce = '00'.repeat(12);
    it.each([
        ['', '', '530f8afbc74536b9a963b4f1c4cb738b'],
        ['\0'.repeat(16), 'cea7403d4d606b6e074ec5d3baf39d18', 'd0d1c8a799996bf0265b98b5d48ab919']
    ])('matches published ciphertext and tag for plaintext %p', async (plaintext, ciphertext, tag) => {
        const expected = Buffer.from(ciphertext + tag, 'hex').toString('base64');
        expect(await aes.gcm.encrypt(key, plaintext, nonce)).toBe(expected);
        expect(await aes.gcm.decrypt(key, expected, nonce)).toBe(plaintext);
    });
});

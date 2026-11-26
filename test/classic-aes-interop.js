const { createCipheriv } = require('node:crypto');
const { aes } = require('..');

it.each([
    ['cbc', '0123456789abcdefFEDCBA9876543210'],
    ['gcm', '0123456789abcdefFEDCBA98']
])('reads native AES-256-%s output with a mixed-case hex IV', async (mode, iv) => {
    const key = '0123456789abcdef'.repeat(2);
    const cipher = createCipheriv('aes-256-' + mode, Buffer.from(key), Buffer.from(iv, 'hex'));
    const message = 'Message from Node crypto';
    const parts = [cipher.update(message, 'utf8'), cipher.final()];
    if (mode === 'gcm') parts.push(cipher.getAuthTag());
    const encoded = Buffer.concat(parts).toString('base64');
    expect(await aes[mode].decrypt(key, encoded, iv)).toBe(message);
    expect(await aes[mode].encrypt(key, message, iv)).toBe(encoded);
});

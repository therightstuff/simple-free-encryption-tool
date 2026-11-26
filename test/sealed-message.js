const { createDecipheriv } = require('node:crypto');
const { aes } = require('..');

describe('sealed messages', () => {
    it('generates non-extractable keys unless export is explicitly enabled', async () => {
        const key = await aes.generateKey();
        expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
        await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow();
        const portable = await aes.generateKey({ extractable: true });
        expect((await crypto.subtle.exportKey('raw', portable)).byteLength).toBe(32);
        await expect(aes.generateKey({ extractable: 'false' })).rejects.toThrow('boolean');
    });

    it.each(['', '\uFEFFhello 🌍', 'abc'.repeat(50000)])('round trips UTF-8 text', async text => {
        const key = await aes.generateKey();
        const message = await aes.seal(key, text);
        expect(await aes.open(key, message)).toBe(text);
        const next = await aes.seal(key, text);
        expect(next.slice(6, 22)).not.toBe(message.slice(6, 22));
    });

    it.each(['', 'Meet at noon 🌍'])('opens extracted bytes with Node crypto', async text => {
        const key = await aes.generateKey({ extractable: true });
        const raw = Buffer.from(await crypto.subtle.exportKey('raw', key));
        const sealed = await aes.seal(key, text);
        const iv = aes.extractIv(sealed);
        const ciphertext = aes.extractCiphertext(sealed);
        const tag = aes.extractTag(sealed);
        expect(iv.byteLength).toBe(12);
        expect(tag.byteLength).toBe(16);
        expect(ciphertext.byteLength).toBe(Buffer.byteLength(text));
        const decipher = createDecipheriv('aes-256-gcm', raw, iv);
        decipher.setAAD(Buffer.from('sfet1'));
        decipher.setAuthTag(tag);
        expect(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString()).toBe(text);
    });

    it('rejects a different key', async () => {
        const key = await aes.generateKey();
        const message = await aes.seal(key, 'message');
        await expect(aes.open(await aes.generateKey(), message)).rejects.toThrow();
    });

    it.each([0, 12, -1])('rejects tampering at byte %i', async offset => {
        const key = await aes.generateKey();
        const message = await aes.seal(key, 'message');
        const [format, encoded] = message.split('.');
        const bytes = Buffer.from(encoded, 'base64');
        bytes[(offset + bytes.length) % bytes.length] ^= 1;
        await expect(aes.open(key, format + '.' + bytes.toString('base64'))).rejects.toThrow();
    });

    it.each([null, 'sfet2.AAAA', 'sfet1.?', 'sfet1.AAAA'])('rejects malformed messages', async message => {
        for (const extract of [aes.extractIv, aes.extractCiphertext, aes.extractTag]) {
            expect(() => extract(message)).toThrow();
        }
        await expect(aes.open(await aes.generateKey(), message)).rejects.toThrow();
    });

    it('rejects invalid keys and non-text plaintext', async () => {
        await expect(aes.seal('password', 'message')).rejects.toThrow('CryptoKey');
        await expect(aes.seal(await aes.generateKey(), '\uD800')).rejects.toThrow('unpaired surrogate');
        await expect(aes.seal(await aes.generateKey(), null)).rejects.toThrow('string');
    });
});

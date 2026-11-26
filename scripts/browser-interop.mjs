import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import sfet from '../index.js';

const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN || '/usr/bin/google-chrome'
});
try {
    const page = await browser.newPage();
    // Serve the actual demo on a secure loopback origin for browser Web Crypto.
    const demo = new URL('../dist/', import.meta.url);
    await page.route('http://localhost/', route => route.fulfill({
        contentType: 'text/html',
        path: fileURLToPath(new URL('index.html', demo))
    }));
    await page.route(/^http:\/\/localhost\/(?:js|css)\/[\w.-]+$/, route => {
        const asset = new URL(route.request().url()).pathname.slice(1);
        return route.fulfill({ path: fileURLToPath(new URL(asset, demo)) });
    });
    await page.goto('http://localhost/');
    const demoFields = {
        'Select AES mode:': 'aesModeSelector',
        'Key (32 chars):': 'aesKey',
        'IV:': 'aesIv',
        'Nonce:': 'aesNonce',
        'Input type:': 'aesSelector',
        'Source File:': 'aesSourceFile',
        'Unencrypted text': 'aesPlaintext',
        'Encrypted text': 'aesEncryptedText'
    };
    await Promise.all(Object.entries(demoFields).map(async ([label, id]) => {
        assert.equal(await page.getByLabel(label, { exact: true }).getAttribute('id'), id);
    }));

    // Transfer a disposable key explicitly to exercise independent Web Crypto runtimes.
    const portable = await sfet.aes.generateKey({ extractable: true });
    const raw = Array.from(new Uint8Array(await crypto.subtle.exportKey('raw', portable)));
    const sealed = await sfet.aes.seal(portable, 'Node → browser');
    const exchanged = await page.evaluate(async ({ raw, sealed }) => {
        const key = await crypto.subtle.importKey('raw', Uint8Array.from(raw), 'AES-GCM', false, ['encrypt', 'decrypt']);
        const text = await window.sfet.aes.open(key, sealed);
        const reply = await window.sfet.aes.seal(key, 'Browser → Node');
        const local = await window.sfet.aes.generateKey();
        if (local.extractable) throw new Error('Browser key is extractable by default');
        const { extractIv, extractCiphertext, extractTag } = window.sfet.aes;
        return { text, reply, parts: [extractIv, extractCiphertext, extractTag].map(fn => Array.from(fn(reply))) };
    }, { raw, sealed });
    assert.equal(exchanged.text, 'Node → browser');
    assert.equal(await sfet.aes.open(portable, exchanged.reply), 'Browser → Node');
    assert.deepEqual(Buffer.concat(exchanged.parts.map(bytes => Buffer.from(bytes))),
        Buffer.from(exchanged.reply.split('.')[1], 'base64'));
    console.log('Sealed messages passed in both directions');

    const key = sfet.utils.randomstring.generateSync(32);
    await Promise.all(['cbc', 'gcm'].map(async mode => {
        const cipher = sfet.aes[mode];
        const parameter = mode === 'cbc' ? cipher.generateIv() : cipher.generateNonce();
        const ciphertext = await cipher.encrypt(key, 'Node → browser', parameter);
        const result = await page.evaluate(async ({ mode, key, parameter, ciphertext }) => {
            const cipher = window.sfet.aes[mode];
            const plaintext = await cipher.decrypt(key, ciphertext, parameter);
            const fresh = mode === 'cbc' ? cipher.generateIv() : cipher.generateNonce();
            return { plaintext, fresh, encrypted: await cipher.encrypt(key, 'Browser → Node', fresh) };
        }, { mode, key, parameter, ciphertext });
        assert.equal(result.plaintext, 'Node → browser');
        assert.equal(await cipher.decrypt(key, result.encrypted, result.fresh), 'Browser → Node');
        console.log(`AES-${mode.toUpperCase()} passed in both directions`);
    }));
} finally {
    await browser.close();
}

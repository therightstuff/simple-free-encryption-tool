/* global fileActionFailure -- Defined by the demo and invoked inside page.evaluate. */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import sfet from '../index.js';

const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN || '/usr/bin/google-chrome'
});
try {
    const page = await browser.newPage();
    page.setDefaultTimeout(5000);
    await page.addInitScript(() => {
        const writes = [];
        const record = (kind, key) => writes.push({ kind, key: String(key ?? '') });
        for (const method of ['setItem', 'removeItem', 'clear']) {
            const original = Storage.prototype[method];
            Object.defineProperty(Storage.prototype, method, {
                configurable: true,
                value(...args) {
                    record(method, args[0]);
                    return original.apply(this, args);
                }
            });
        }
        const open = indexedDB.open.bind(indexedDB);
        indexedDB.open = (...args) => {
            record('indexedDB.open', args[0]);
            return open(...args);
        };
        window.__sfetStorageWrites = writes;
    });
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
    const actionRequests = [];
    page.on('request', request => actionRequests.push(request.url()));
    await page.locator('#aesPlaintext').fill('Draft retained during initialization');
    await page.evaluate(() => window.renderDemo());
    assert.equal(await page.locator('#aesPlaintext').inputValue(), 'Draft retained during initialization');
    assert.equal(await page.locator('#sfetDemo').count(), 1,
        'rendering the demo again must not replace or duplicate the live page');
    const labelableFields = [
        'md5Plaintext',
        'md5Hash',
        'sha256Plaintext',
        'sha256Hash',
        'keySize',
        'rsaPublicKey',
        'rsaPrivateKey',
        'rsaPlaintext',
        'rsaEncryptedText',
        'rsaSignature',
        'aesModeSelector',
        'aesKey',
        'aesIv',
        'aesNonce',
        'aesSelector',
        'aesSourceFile',
        'aesPlaintext',
        'aesEncryptedText'
    ];
    await Promise.all(labelableFields.map(async (id) => {
        assert.equal(await page.locator(`#${id}`).evaluate(element => element.labels?.[0]?.htmlFor), id,
            `${id} must have an explicit label`);
    }));
    assert.match(await page.locator('#rsaVerified').getAttribute('aria-label') ||
        await page.locator('#rsaVerified').getAttribute('aria-labelledby') || '', /.+/);

    await Promise.all(['demo-aes', 'demo-rsa', 'demo-sha256', 'demo-md5'].map(async (id) => {
        assert.equal(await page.locator(`#${id}`).evaluate(element => element.open), true,
            `${id} must be expanded initially`);
    }));
    assert.equal(await page.locator('#aesModeSelector').inputValue(), 'gcm');
    await Promise.all([['aesKeyStatus', 'aesKey'], ['aesStatus', 'aesPlaintext'], ['aesDecryptStatus', 'aesEncryptedText']].map(async ([statusId, fieldId]) => {
        assert.equal(await page.locator(`#${statusId}`).evaluate((status, id) => {
            const field = document.getElementById(id);
            return status.parentElement?.contains(field) && Boolean(status.compareDocumentPosition(field) & Node.DOCUMENT_POSITION_FOLLOWING);
        }, fieldId), true, `${statusId} must be directly above the field for its action`);
    }));
    assert.equal(await page.locator('#rsaStatus').evaluate(status =>
        status.parentElement?.contains(document.querySelector('#generateRsaKeys'))), true,
    'RSA generation feedback must stay with its action control');
    await Promise.all(['rsaTextStatus', 'rsaSigningStatus'].map(async (statusId) => {
        assert.equal(await page.locator(`#${statusId}`).evaluate(status =>
            status.parentElement?.querySelectorAll('button').length === 2), true,
        `${statusId} must stay with its action controls`);
    }));
    /* eslint-disable no-await-in-loop -- One page shares viewport and mode; parallel changes would race the assertions. */
    for (const width of [390, 1280]) {
        await page.setViewportSize({ width, height: 900 });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true,
            `demo must not overflow at ${width}px`);
    }
    /* eslint-enable no-await-in-loop */
    const md5Summary = page.locator('#demo-md5 summary');
    await md5Summary.focus();
    await page.keyboard.press('Space');
    assert.equal(await page.locator('#demo-md5').evaluate(element => element.open), false);
    await page.keyboard.press('Space');
    assert.equal(await page.locator('#demo-md5').evaluate(element => element.open), true);

    const copyControls = [
        'copy-md5Plaintext',
        'copy-md5Hash',
        'copy-sha256Plaintext',
        'copy-sha256Hash',
        'copy-rsaPublicKey',
        'copy-rsaPrivateKey',
        'copy-rsaPlaintext',
        'copy-rsaEncryptedText',
        'copy-rsaSignature',
        'copy-rsaVerified',
        'copy-aesKey',
        'copy-aesIv',
        'copy-aesNonce',
        'copy-aesPlaintext',
        'copy-aesEncryptedText',
    ];
    await Promise.all(copyControls.map(async (testId) => {
        const control = page.getByTestId(testId);
        assert.match(await control.getAttribute('aria-label') || '', /copy/i);
        assert.match(await control.getAttribute('title') || '', /copy/i);
    }));
    await Promise.all(['download-rsaPublicKey', 'download-rsaPrivateKey'].map(async (testId) => {
        const control = page.getByTestId(testId);
        assert.match(await control.getAttribute('aria-label') || '', /download|save/i);
        assert.match(await control.getAttribute('title') || '', /download|save/i);
        await assertIconFitsControl(control);
    }));
    /* eslint-disable no-await-in-loop -- One page shares viewport and mode; parallel changes would race the assertions. */
    for (const width of [390, 1280]) {
        await page.setViewportSize({ width, height: 900 });
        for (const testId of [...copyControls, 'download-rsaPublicKey', 'download-rsaPrivateKey']) {
            if (testId === 'copy-aesIv') await page.locator('#aesModeSelector').selectOption('cbc');
            if (testId === 'copy-aesNonce') await page.locator('#aesModeSelector').selectOption('gcm');
            await assertIconFitsControl(page.getByTestId(testId));
        }
    }
    /* eslint-enable no-await-in-loop */
    await page.getByTestId('encrypt-rsa').click();
    await assertStatus(page, '#rsaTextStatus', /public key/i);
    await page.getByTestId('decrypt-rsa').click();
    await assertStatus(page, '#rsaTextStatus', /private key/i);
    await page.getByTestId('sign-rsa').click();
    await assertStatus(page, '#rsaSigningStatus', /private key/i);
    await page.getByTestId('verify-rsa').click();
    await assertStatus(page, '#rsaSigningStatus', /public key/i);
    await page.getByTestId('decrypt-aes').click();
    assert.match(await page.getByTestId('aes-decrypt-status').textContent() || '', /32-character key/i);
    assert.equal(await page.locator('#aesKey').getAttribute('aria-invalid'), 'true');
    assert.equal(await page.getByTestId('encrypt-aes').evaluate(button =>
        button.closest('.transform-grid')?.contains(document.querySelector('#aesPlaintext'))), true);

    const aesKey = 'A'.repeat(32);
    await page.locator('#aesKey').fill(aesKey);
    await page.locator('#aesEncryptedText').fill('not-valid-ciphertext');
    await page.getByTestId('decrypt-aes').click();
    await assertStatus(page, '#aesDecryptStatus', /saved nonce/i);
    assert.equal(await page.locator('#aesNonce').getAttribute('aria-invalid'), 'true');
    assert.equal(await page.locator('#aesNonce').evaluate(field => field.classList.contains('input-error')), true);

    await page.locator('#aesKey').fill('short key');
    await page.getByTestId('encrypt-aes').click();
    await assertStatus(page, '#aesStatus', /32-character key/i);
    assert.equal((await page.getByTestId('aes-decrypt-status').textContent() || '').trim(), '',
        'an encryption attempt must clear superseded AES decryption feedback even when encryption fails');
    assert.equal(await page.locator('#aesNonce').getAttribute('aria-invalid'), null,
        'a replacement encryption attempt must clear superseded AES decryption invalid state even when it fails');
    assert.equal(await page.locator('#aesNonce').evaluate(field => field.classList.contains('input-error')), false,
        'a replacement encryption attempt must clear superseded AES decryption error styling even when it fails');

    await page.locator('#aesKey').fill(aesKey);
    await page.locator('#aesPlaintext').fill('Corrected AES input');
    await page.getByTestId('encrypt-aes').click();
    await page.waitForFunction(() => document.querySelector('#aesEncryptedText').value !== 'not-valid-ciphertext');
    await assertStatus(page, '#aesStatus', /encryption successful/i);
    assert.equal((await page.getByTestId('aes-decrypt-status').textContent() || '').trim(), '',
        'successful encryption must not leave superseded AES decryption feedback visible');
    await Promise.all(['aesKey', 'aesIv', 'aesNonce', 'aesPlaintext', 'aesEncryptedText'].map(async (id) => {
        assert.equal(await page.locator(`#${id}`).getAttribute('aria-invalid'), null,
            `${id} must clear stale invalid state after successful AES encryption`);
        assert.equal(await page.locator(`#${id}`).evaluate(field => field.classList.contains('input-error')), false,
            `${id} must clear stale visual error state after successful AES encryption`);
    }));
    await page.evaluate(() => {
        Object.defineProperty(navigator, 'clipboard', {
            configurable: true,
            value: {
                writeText(value) {
                    window.__sfetCopiedValue = value;
                    return Promise.resolve();
                }
            }
        });
    });
    await page.getByTestId('copy-aesKey').click();
    await assertStatus(page, '#aesKeyStatus', /copied/i);
    assert.equal(await page.evaluate(() => window.__sfetCopiedValue), aesKey);

    await page.evaluate(() => {
        const prototype = Object.getPrototypeOf(navigator);
        Object.defineProperty(prototype, 'clipboard', { configurable: true, value: undefined });
        delete navigator.clipboard;
        // eslint-disable-next-line no-restricted-properties -- This stub verifies the supported legacy clipboard fallback; removing it loses compatibility coverage.
        document.execCommand = command => {
            window.__sfetFallbackCommand = command;
            return command === 'copy';
        };
    });
    await page.getByTestId('copy-aesKey').click();
    assert.equal(await page.evaluate(() => window.__sfetFallbackCommand), 'copy');
    await assertStatus(page, '#aesKeyStatus', /copied/i);

    await page.evaluate(() => {
        Object.defineProperty(navigator, 'clipboard', {
            configurable: true,
            value: { writeText: () => Promise.reject(new Error('Clipboard permission denied')) }
        });
    });
    await page.getByTestId('copy-aesKey').click();
    await assertStatus(page, '#aesKeyStatus', /could not copy|copy failed/i);
    assert.doesNotMatch(await page.getByTestId('aes-key-status').textContent() || '', new RegExp(aesKey));

    const publicPem = '-----BEGIN PUBLIC KEY-----\npublic-key\n-----END PUBLIC KEY-----\n';
    const privatePem = '-----BEGIN PRIVATE KEY-----\nprivate-key\n-----END PRIVATE KEY-----\n';
    await page.evaluate(() => {
        window.__rsaGenerationCalls = 0;
        window.sfet.rsa.generateKeys = () => new Promise(resolve => {
            window.__rsaGenerationCalls += 1;
            window.__resolveRsaGeneration = resolve;
        });
    });
    await page.getByTestId('generate-rsa-keys').click();
    assert.equal(await page.getByTestId('generate-rsa-keys').isDisabled(), true);
    assert.equal(await page.locator('#keySize').isDisabled(), true);
    await page.waitForFunction(() => typeof window.__resolveRsaGeneration === 'function');
    await page.evaluate(() => window.generateKeys());
    assert.equal(await page.evaluate(() => window.__rsaGenerationCalls), 1,
        'RSA key generation must ignore a second request while one is active');
    await page.getByTestId('copy-aesKey').click();
    await assertStatus(page, '#aesKeyStatus', /could not copy/i);
    await page.evaluate(() => window.__resolveRsaGeneration({
        public: 'generated public key', private: 'generated private key', keySize: 2048, time: 1
    }));
    await assertStatus(page, '#rsaStatus', /keys generated/i);
    assert.doesNotMatch(await page.getByTestId('aes-key-status').textContent() || '', /keys generated/i);
    assert.equal(await page.getByTestId('generate-rsa-keys').isDisabled(), false);
    assert.equal(await page.locator('#keySize').isDisabled(), false);
    await page.evaluate(() => {
        window.sfet.rsa.generateKeys = () => Promise.reject(new Error('generation failed'));
    });
    await page.getByTestId('generate-rsa-keys').click();
    assert.equal(await page.getByTestId('generate-rsa-keys').isDisabled(), true);
    await assertStatus(page, '#rsaStatus', /unable to generate/i);
    assert.equal(await page.getByTestId('generate-rsa-keys').isDisabled(), false);
    assert.equal(await page.locator('#keySize').isDisabled(), false);

    await page.locator('#rsaPublicKey').fill('');
    await page.locator('#rsaPrivateKey').fill('');
    assert.equal(await page.getByTestId('download-rsaPublicKey').isDisabled(), true);
    assert.equal(await page.getByTestId('download-rsaPrivateKey').isDisabled(), true);
    await page.locator('#rsaPublicKey').fill(publicPem);
    await page.locator('#rsaPrivateKey').fill(privatePem);

    const publicDownloadPromise = page.waitForEvent('download');
    await page.getByTestId('download-rsaPublicKey').click();
    const publicDownload = await publicDownloadPromise;
    assert.equal(publicDownload.suggestedFilename(), 'sfet-public-key.pem');
    assert.equal(await readFile(await publicDownload.path(), 'utf8'), publicPem);

    const privateDownloadPromise = page.waitForEvent('download');
    await page.getByTestId('download-rsaPrivateKey').click();
    const privateDownload = await privateDownloadPromise;
    assert.equal(privateDownload.suggestedFilename(), 'sfet-private-key.pem');
    assert.equal(await readFile(await privateDownload.path(), 'utf8'), privatePem);

    await page.locator('#rsaPrivateKey').fill('');
    assert.equal(await page.getByTestId('download-rsaPrivateKey').isDisabled(), true);

    await page.locator('#sha256Plaintext').fill('local-only checksum');
    await page.getByTestId('hash-sha256').click();
    await page.waitForFunction(() => document.querySelector('#sha256Hash').value.length > 0);

    const plaintext = 'Browser-only AES interaction';
    await page.locator('#aesPlaintext').fill(plaintext);
    await page.getByTestId('encrypt-aes').click();
    await page.waitForFunction(() => document.querySelector('#aesEncryptedText').value.length > 0);
    const firstCiphertext = await page.locator('#aesEncryptedText').inputValue();
    const firstNonce = await page.locator('#aesNonce').inputValue();
    await page.getByTestId('encrypt-aes').click();
    await page.waitForFunction(({ ciphertext, nonce }) => {
        return document.querySelector('#aesEncryptedText').value !== ciphertext &&
            document.querySelector('#aesNonce').value !== nonce;
    }, { ciphertext: firstCiphertext, nonce: firstNonce });
    const ciphertextToDecrypt = await page.locator('#aesEncryptedText').inputValue();
    await page.locator('#aesEncryptedText').fill('not-valid-ciphertext');
    await page.getByTestId('decrypt-aes').click();
    await assertStatus(page, '#aesDecryptStatus', /unable to decrypt/i);
    await Promise.all(['aesKey', 'aesNonce', 'aesEncryptedText'].map(async (id) => {
        assert.equal(await page.locator(`#${id}`).getAttribute('aria-invalid'), 'true',
            `${id} must identify the failed AES decryption input`);
        assert.equal(await page.locator(`#${id}`).evaluate(field => field.classList.contains('input-error')), true,
            `${id} must visibly identify the failed AES decryption input`);
    }));
    await page.locator('#aesEncryptedText').fill(ciphertextToDecrypt);
    await page.getByTestId('decrypt-aes').click();
    await page.waitForFunction(value => document.querySelector('#aesPlaintext').value === value, plaintext);
    await assertStatus(page, '#aesDecryptStatus', /decryption successful/i);
    await Promise.all(['aesKey', 'aesIv', 'aesNonce', 'aesPlaintext', 'aesEncryptedText'].map(async (id) => {
        assert.equal(await page.locator(`#${id}`).getAttribute('aria-invalid'), null,
            `${id} must clear stale invalid state after successful AES decryption`);
        assert.equal(await page.locator(`#${id}`).evaluate(field => field.classList.contains('input-error')), false,
            `${id} must clear stale visual error state after successful AES decryption`);
    }));
    assert.deepEqual(actionRequests, []);

    assert.match(await page.evaluate(() => fileActionFailure('encrypted', {
        message: 'Maximum call stack size exceeded'
    })), /too large.*not changed/i);
    assert.match(await page.evaluate(() => fileActionFailure('encrypted', {
        message: 'Unexpected browser failure'
    })), /not changed.*smaller file/i);

    await page.locator('#aesSelector').selectOption('file');
    await page.locator('#aesSourceFile').setInputFiles({
        name: 'sample.bin',
        mimeType: 'application/octet-stream',
        buffer: Buffer.from([0, 1, 2, 3])
    });
    await page.evaluate(() => {
        window.sfet.aes.gcm.encrypt = () => Promise.reject(new RangeError('Maximum call stack size exceeded'));
        window.sfet.aes.gcm.decrypt = () => Promise.reject(new RangeError('Maximum call stack size exceeded'));
    });
    await page.getByTestId('encrypt-aes-file').click();
    await assertStatus(page, '#aesFileStatus', /too large.*not changed/i);
    assert.equal(await page.locator('#aesSourceFile').getAttribute('aria-invalid'), 'true');
    await page.getByTestId('decrypt-aes-file').click();
    await assertStatus(page, '#aesFileStatus', /too large.*not changed/i);
    assert.equal(await page.locator('#aesSourceFile').getAttribute('aria-invalid'), 'true');

    const browserStorage = await page.evaluate(() => ({
        writes: window.__sfetStorageWrites,
        cookie: document.cookie,
        local: { ...localStorage },
        session: { ...sessionStorage }
    }));
    assert.deepEqual(browserStorage.writes, []);
    assert.equal(browserStorage.cookie, '');
    assert.deepEqual(browserStorage.local, {});
    assert.deepEqual(browserStorage.session, {});

    await page.reload();
    assert.equal(await page.locator('#aesPlaintext').inputValue(), '');
    assert.equal(await page.locator('#aesKey').inputValue(), '');

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

async function assertStatus(page, selector, expected) {
    await page.waitForFunction(({ selector, pattern }) => {
        const status = document.querySelector(selector);
        return Boolean(status && new RegExp(pattern, 'i').test(status.textContent || ''));
    }, { selector, pattern: expected.source });
    assert.match(await page.locator(selector).textContent() || '', expected);
}

async function assertIconFitsControl(control) {
    assert.equal(await control.locator('svg').getAttribute('viewBox'), '0 0 24 24');
    const { button, icon } = await control.evaluate(element => ({
        button: element.getBoundingClientRect().toJSON(),
        icon: element.querySelector('svg').getBoundingClientRect().toJSON()
    }));
    assert.equal(icon.width > 0 && icon.height > 0, true);
    assert.equal(icon.width < button.width && icon.height < button.height, true);
    assert.equal(icon.width / button.width >= 0.5 && icon.height / button.height >= 0.5, true);
    assert.equal(Math.abs((icon.x + icon.width / 2) - (button.x + button.width / 2)) <= 1, true);
    assert.equal(Math.abs((icon.y + icon.height / 2) - (button.y + button.height / 2)) <= 1, true);
}

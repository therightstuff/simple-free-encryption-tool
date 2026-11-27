import js from '@eslint/js';
import sonarjs from 'eslint-plugin-sonarjs';
import html from 'eslint-plugin-html';
import globals from 'globals';

export default [
    // These directories contain dependencies, coverage output and generated/vendor scripts.
    { ignores: ['node_modules/**', 'coverage/**', 'dist/js/**'] },
    {
        files: ['**/*.js', '**/*.mjs', 'dist/index.html'],
        plugins: { sonarjs, html },
        languageOptions: {
            globals: { ...globals.node, ...globals.browser },
        },
        rules: {
            ...js.configs.recommended.rules,
            ...sonarjs.configs.recommended.rules,
            'no-await-in-loop': 'error',
            'no-restricted-properties': ['error', { property: 'execCommand', message: 'Deprecated clipboard API; use navigator.clipboard.writeText.' }],
        },
    },
    { files: ['**/*.js'], languageOptions: { sourceType: 'commonjs' } },
    {
        files: ['test/**/*.js'],
        languageOptions: { globals: globals.jest },
    },
    {
        files: ['dist/index.html'],
        languageOptions: { sourceType: 'script', globals: { $: 'readonly', toastr: 'readonly', sfet: 'readonly' } },
    },
];

import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

/**
 * Lint configuration.
 *
 * Strict, but only for rules that catch real defects in this codebase. The stylistic rules
 * that TypeScript and Prettier already cover are left off, so there is one formatter rather
 * than two disagreeing ones.
 */
export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'src-tauri/**',
      'src-tauri/target/**',
      // This file is linted as plain config, not as part of the type-aware project.
      'eslint.config.js',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      globals: globals.browser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,

      // The engine's shapes are exact unions; an unchecked index or a loose cast in a
      // renderer is where a silent wrong value would come from.
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/consistent-type-imports': ['error', { prefer: 'type-imports' }],
      '@typescript-eslint/no-unnecessary-condition': 'off',
      '@typescript-eslint/restrict-template-expressions': [
        'error',
        { allowNumber: true, allowBoolean: true, allowNullish: true },
      ],

      // A11y, because a tool people use for hours must be operable.
      'jsx-a11y/alt-text': 'off',
    },
  },
  {
    // Vite's config file runs in Node, not the browser.
    files: ['vite.config.ts'],
    languageOptions: { globals: globals.node },
  },
);

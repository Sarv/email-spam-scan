// The house style, as rules rather than as prose.
//
// Adapted from the sibling package `@sarv-in/email-chat-view`, deliberately:
// two Sarv OSS repos that a contributor might open in the same afternoon
// should not disagree about import order. The differences from that config are
// only where this package's risk profile differs, and each is commented.
//
// Formatting is NOT here. Prettier owns it (`.prettierrc.json`), and
// `eslint-config-prettier` switches off every stylistic rule that would argue
// with it, so the two can never disagree about the same line.
import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import importX from 'eslint-plugin-import-x';
import regexp from 'eslint-plugin-regexp';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['dist/**', 'coverage/**', 'node_modules/**'],
  },

  js.configs.recommended,
  ...tseslint.configs.recommended,
  importX.flatConfigs.recommended,
  importX.flatConfigs.typescript,
  regexp.configs['flat/recommended'],

  {
    files: ['**/*.{ts,js,mjs}'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      // The scanner runs in Node AND in a browser (the `verdict` and
      // `identity` entries are browser-safe by contract). Which globals a
      // given module may actually touch is enforced by its entry point and by
      // types, not by this list.
      globals: { ...globals.browser, ...globals.node },
    },
    settings: {
      'import-x/resolver': {
        typescript: { project: './tsconfig.json' },
      },
    },
    rules: {
      // --- ESM that actually resolves ------------------------------------
      //
      // The emitted ESM is consumed by Node with no bundler, so a relative
      // import without the `.js` extension resolves in the editor,
      // type-checks cleanly, builds without complaint, and then throws
      // ERR_MODULE_NOT_FOUND in somebody's app. It is invisible in review.
      'import-x/extensions': [
        'error',
        'ignorePackages',
        { ts: 'never', js: 'always', mjs: 'always' },
      ],

      'import-x/no-cycle': ['error', { maxDepth: Infinity }],
      'import-x/no-useless-path-segments': 'error',
      'import-x/no-named-as-default': 'off',
      'import-x/no-named-as-default-member': 'off',

      'import-x/order': [
        'error',
        {
          groups: ['builtin', 'external', 'internal', 'parent', 'sibling', 'index'],
          'newlines-between': 'always',
          alphabetize: { order: 'asc', caseInsensitive: true },
        },
      ],

      // --- Types -----------------------------------------------------------
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports', fixStyle: 'inline-type-imports' },
      ],
      '@typescript-eslint/no-import-type-side-effects': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' },
      ],

      // --- Regex: the ReDoS rules -------------------------------------------
      //
      // ERRORS here, where the sibling package has to tolerate a warning
      // backlog it inherited. This repo starts clean, and its input is worse:
      // the whole point of a spam scanner is that it runs on mail an attacker
      // chose, at ingest, on the thread that is also delivering everything
      // else. A super-linear pattern against a 5 MB body is not a slow scan,
      // it is a mail flow that stops.
      //
      // The house rule that follows from this: a contributed RULE is data — a
      // word, a domain, a weight — matched by the engine. Contributors do not
      // write patterns. See CONTRIBUTING.md.
      'regexp/no-super-linear-backtracking': 'error',
      'regexp/no-potentially-useless-backreference': 'error',
      'regexp/optimal-quantifier-concatenation': 'error',

      // --- Purity ------------------------------------------------------------
      //
      // A library that logs is a library that pollutes somebody else's console
      // and cannot be silenced. Report through the returned verdict.
      'no-console': 'error',
      'no-var': 'error',
      'prefer-const': 'error',
      'prefer-template': 'error',
      'object-shorthand': ['error', 'properties'],
      eqeqeq: ['error', 'always', { null: 'ignore' }],
    },
  },

  // --- Tests -----------------------------------------------------------------
  {
    files: ['test/**/*.ts'],
    rules: {
      // A fixture is a header block a real MTA produced, and an assertion's
      // throwaway pattern never sees hostile input. Neither is the package's
      // own regex surface, which is what the ReDoS rules exist to protect.
      'regexp/no-super-linear-backtracking': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },

  {
    files: ['examples/**', 'scripts/**'],
    rules: {
      // Printing IS the output here; the ban exists to keep the LIBRARY quiet.
      'no-console': 'off',
      // They import the BUILT `dist/` by package specifier, which does not
      // exist until `pnpm build` has run — so the resolver cannot see it.
      'import-x/no-unresolved': 'off',
    },
  },

  // Last, so it wins: turns off every rule Prettier would fight over.
  prettier,
);

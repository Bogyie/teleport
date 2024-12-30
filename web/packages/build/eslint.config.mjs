/**
 * Teleport
 * Copyright (C) 2024 Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactPlugin from 'eslint-plugin-react';
import reactHooksPlugin from 'eslint-plugin-react-hooks';
import importPlugin from 'eslint-plugin-import';
import jestPlugin from 'eslint-plugin-jest';
import testingLibraryPlugin from 'eslint-plugin-testing-library';
import jestDomPlugin from 'eslint-plugin-jest-dom';
import simpleImportSort from 'eslint-plugin-simple-import-sort';
import globals from 'globals';

import tsConfigBase from '../../../tsconfig.json' with { type: 'json' };

const ourPackages = new Set(
  Object.keys(tsConfigBase.compilerOptions.paths).map(
    // Remove extra '/*' if present in the package name.
    packageName => packageName.split('/')[0]
  )
);
const appPackages = ['teleport', 'e-teleport', 'teleterm'];
const libraryPackages = [...ourPackages].filter(
  pkg => !appPackages.includes(pkg)
);

export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      '**/*_pb.*',
      '.eslintrc.js',
      '**/tshd/**/*_pb.js',
      // WASM generated files
      'web/packages/teleport/src/ironrdp/pkg',
      'web/packages/teleterm/build',
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  reactPlugin.configs.flat.recommended,
  reactPlugin.configs.flat['jsx-runtime'],
  importPlugin.flatConfigs.errors,
  importPlugin.flatConfigs.warnings,
  importPlugin.flatConfigs.typescript,
  {
    settings: {
      react: {
        version: 'detect',
      },
    },
    languageOptions: {
      ecmaVersion: 6,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.node,
        expect: 'readonly',
        jest: 'readonly',
      },
      parser: tseslint.parser,
    },
    plugins: {
      // There is no flat config available.
      'react-hooks': reactHooksPlugin,
      'simple-import-sort': simpleImportSort,
    },
    rules: {
      ...reactHooksPlugin.configs.recommended.rules,
      'import/first': 'error',
      'import/newline-after-import': 'error',
      'import/no-duplicates': 'error',
      'simple-import-sort/imports': [
        'error',
        {
          // Type imports are put at the end of each group. simple-import-sort appends \u0000 to
          // type imports. Each import is matched against all regexes on the `from` string. The
          // import ends up at the regex with the longest match. In case of a tie, the first
          // matching regex wins.
          groups: [
            // Side effect imports.
            ['^\\u0000'],
            // Node.js builtins prefixed with `node:`.
            ['^node:', '^node:.*\\u0000$'],
            // Things that start with a letter (or digit or underscore), or `@` followed by a letter.
            // Using positive lookahead to keep the match length small so that type imports from our
            // packages go into the correct group, which uses .* (and thus matches the whole length
            // of the import).
            ['^@?\\w', '^@?\\w(?=.*\\u0000$)'],
            // Our library packages.
            [
              `^(${libraryPackages.join('|')})(/|$)`,
              `^(${libraryPackages.join('|')})(/?.*\\u0000$)`,
            ],
            // Our app packages.
            [
              `^(${appPackages.join('|')})(/|$)`,
              `^(${appPackages.join('|')})(/?.*\\u0000$)`,
            ],
            // Absolute imports and other imports such as Vue-style `@/foo`.
            // Anything not matched in another group.
            ['(?<!\\u0000)$', '(?<=\\u0000)$'],
            // Relative imports.
            // Anything that starts with a dot.
            ['^\\.', '^\\..*\\u0000$'],
          ],
        },
      ],
      'simple-import-sort/exports': 'error',
      // typescript-eslint recommends to turn import/no-unresolved off.
      // https://typescript-eslint.io/troubleshooting/typed-linting/performance/#eslint-plugin-import
      'import/no-unresolved': 'off',
      '@typescript-eslint/no-unused-expressions': [
        'error',
        { allowShortCircuit: true, allowTernary: true, enforceForJSX: true },
      ],
      '@typescript-eslint/no-empty-object-type': [
        'error',
        // with-single-extends is needed to allow for interface extends like we have in jest.d.ts.
        { allowInterfaces: 'with-single-extends' },
      ],

      // <TODO> Enable these recommended typescript-eslint rules after fixing existing issues.
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-this-alias': 'off',
      // </TODO>

      'no-case-declarations': 'off',
      'prefer-const': 'off',
      'no-var': 'off',
      'prefer-rest-params': 'off',

      'no-console': 'warn',
      'no-trailing-spaces': 'error',
      'react/jsx-no-undef': 'error',
      'react/jsx-pascal-case': 'error',
      'react/no-danger': 'error',
      'react/jsx-no-duplicate-props': 'error',
      'react/jsx-sort-prop-types': 'off',
      'react/jsx-sort-props': 'off',
      'react/jsx-uses-vars': 'warn',
      'react/no-did-mount-set-state': 'warn',
      'react/no-did-update-set-state': 'warn',
      'react/no-unknown-property': 'warn',
      'react/prop-types': 'off',
      'react/jsx-wrap-multilines': 'warn',
      // allowExpressions allow single expressions in a fragment eg: <>{children}</>
      // https://github.com/jsx-eslint/eslint-plugin-react/blob/f83b38869c7fc2c6a84ef8c2639ac190b8fef74f/docs/rules/jsx-no-useless-fragment.md#allowexpressions
      'react/jsx-no-useless-fragment': ['error', { allowExpressions: true }],
      'react/display-name': 'off',
      'react/no-children-prop': 'warn',
      'react/no-unescaped-entities': 'warn',
      'react/jsx-key': 'warn',
      'react/jsx-no-target-blank': 'warn',

      'react-hooks/rules-of-hooks': 'warn',
      'react-hooks/exhaustive-deps': 'warn',
    },
  },
  {
    files: ['**/*.test.{ts,tsx,js,jsx}'],
    languageOptions: {
      globals: globals.jest,
    },
    plugins: {
      jest: jestPlugin,
      'testing-library': testingLibraryPlugin,
      'jest-dom': jestDomPlugin,
    },
    rules: {
      ...jestPlugin.configs['flat/recommended'].rules,
      ...testingLibraryPlugin.configs['flat/react'].rules,
      ...jestDomPlugin.configs['flat/recommended'].rules,
      'jest/prefer-called-with': 'off',
      'jest/prefer-expect-assertions': 'off',
      'jest/consistent-test-it': 'off',
      'jest/no-try-expect': 'off',
      'jest/no-hooks': 'off',
      'jest/no-disabled-tests': 'off',
      'jest/prefer-strict-equal': 'off',
      'jest/prefer-inline-snapshots': 'off',
      'jest/require-top-level-describe': 'off',
      'jest/no-large-snapshots': ['warn', { maxSize: 200 }],
    },
  },
  {
    // Allow require imports in .js files, as migrating our project to ESM modules requires a lot of
    // changes.
    files: ['**/*.js'],
    rules: {
      '@typescript-eslint/no-require-imports': 'warn',
    },
  }
);

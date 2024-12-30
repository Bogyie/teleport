module.exports = {
  arrowParens: 'avoid',
  printWidth: 80,
  bracketSpacing: true,
  plugins: [
    require('@ianvs/prettier-plugin-sort-imports'),
  ],
  importOrder: [
    '<THIRD_PARTY_MODULES>',
    '',
    '<BUILTIN_MODULES>',
    '',
    '^(design|build|shared|teleport|teleport-e)/(.*)$',
    '^@gravitational/(.*)$',
    '',
    '^[./]',
  ],
  importOrderParserPlugins: [
    'typescript',
    'jsx',
    'decorators-legacy',
  ],
  importOrderTypeScriptVersion: '5.0.0',
  semi: true,
  singleQuote: true,
  tabWidth: 2,
  trailingComma: 'es5',
};

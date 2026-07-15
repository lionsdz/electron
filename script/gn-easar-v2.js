#!/usr/bin/env node

const build = require('./lib/easar-v2-build');

const parseArguments = argv => {
  const scalarFlags = new Set([
    '--base',
    '--out',
    '--data-key-file',
    '--signing-private-key-file',
    '--signing-public-key-file',
    '--key-id-manifest',
    '--epoch',
    '--block-size-log2',
    '--compression-level'
  ]);
  const values = new Map();
  let files;
  let compression = true;
  let trustWindowsKeyAcl = false;
  for (let index = 0; index < argv.length;) {
    const flag = argv[index++];
    if (flag === '--trust-windows-key-acl') {
      if (trustWindowsKeyAcl) {
        throw new build.EasrBuildError(
          'ERR_EASR_BUILD_ARGUMENT',
          'duplicate --trust-windows-key-acl'
        );
      }
      trustWindowsKeyAcl = true;
      continue;
    }
    if (flag === '--no-compress') {
      if (!compression) {
        throw new build.EasrBuildError(
          'ERR_EASR_BUILD_ARGUMENT', 'duplicate --no-compress'
        );
      }
      compression = false;
      continue;
    }
    if (flag === '--files') {
      if (files) {
        throw new build.EasrBuildError(
          'ERR_EASR_BUILD_ARGUMENT', 'duplicate --files'
        );
      }
      files = [];
      while (index < argv.length && !argv[index].startsWith('--')) {
        files.push(argv[index++]);
      }
      continue;
    }
    if (!scalarFlags.has(flag) || values.has(flag) || index >= argv.length ||
        argv[index].startsWith('--')) {
      throw new build.EasrBuildError(
        'ERR_EASR_BUILD_ARGUMENT',
        'invalid or duplicate GN EASR argument: ' + String(flag)
      );
    }
    values.set(flag, argv[index++]);
  }
  const integer = (flag, fallback) => {
    if (!values.has(flag)) return fallback;
    const value = Number(values.get(flag));
    if (!Number.isInteger(value)) {
      throw new build.EasrBuildError(
        'ERR_EASR_BUILD_ARGUMENT', flag + ' must be an integer'
      );
    }
    return value;
  };
  return {
    base: values.get('--base'),
    files,
    output: values.get('--out'),
    dataKeyFile: values.get('--data-key-file'),
    signingPrivateKeyFile: values.get('--signing-private-key-file'),
    signingPublicKeyFile: values.get('--signing-public-key-file'),
    keyIdManifest: values.get('--key-id-manifest'),
    epoch: values.get('--epoch'),
    blockSizeLog2: integer('--block-size-log2', 16),
    compressionLevel: integer('--compression-level', 9),
    compression,
    trustWindowsKeyAcl
  };
};

const main = argv => build.packGnAsar(parseArguments(argv));

if (require.main === module) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write((error.code ? error.code + ': ' : '') +
      (error.message || String(error)) + '\n');
    process.exitCode = 1;
  }
}

module.exports = { main, parseArguments };

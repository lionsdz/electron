#!/usr/bin/env node

const build = require('./lib/easar-v2-build');

const parseArguments = argv => {
  const known = new Set([
    '--data-key-file',
    '--signing-public-key-file',
    '--minimum-epoch',
    '--out',
    '--key-id-manifest-out'
  ]);
  const values = new Map();
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
    if (!known.has(flag) || values.has(flag) || index >= argv.length ||
        argv[index].startsWith('--')) {
      throw new build.EasrBuildError(
        'ERR_EASR_BUILD_ARGUMENT',
        'invalid or duplicate key-header argument: ' + String(flag)
      );
    }
    values.set(flag, argv[index++]);
  }
  return {
    dataKeyFile: values.get('--data-key-file'),
    signingPublicKeyFile: values.get('--signing-public-key-file'),
    minimumEpoch: values.get('--minimum-epoch'),
    output: values.get('--out'),
    keyIdManifestOutput: values.get('--key-id-manifest-out'),
    trustWindowsKeyAcl
  };
};

const main = argv => build.generateKeyHeader(parseArguments(argv));

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

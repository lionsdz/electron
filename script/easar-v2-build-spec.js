#!/usr/bin/env node

/* global BigInt */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const asar = require('asar');
const build = require('./lib/easar-v2-build');
const format = require('./lib/easar-v2-format');
const hash = require('./gn-asar-hash');
const gnEasr = require('./gn-easar-v2');
const keyHeader = require('./generate-easar-v2-key-header');

const tests = [];
const test = (name, body) => tests.push({ name, body });
const trustWindowsKeyAcl = process.platform === 'win32';

const expectCode = (body, code) => {
  assert.throws(body, error => {
    assert.strictEqual(error && error.code, code);
    return true;
  });
};

const withWorkspace = async body => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'easr-v2-build-spec-'));
  try {
    return await body(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
};

const writeSecret = (filename, contents) => {
  fs.writeFileSync(filename, contents, { mode: 0o600 });
  if (process.platform !== 'win32') fs.chmodSync(filename, 0o600);
};

const makeKeyFiles = root => {
  const dataKey = Buffer.from(Array.from({ length: 32 }, (_, index) =>
    index + 1));
  const pair = crypto.generateKeyPairSync('ed25519');
  const dataKeyFile = path.join(root, 'data.key');
  const privateKeyFile = path.join(root, 'signing-private.pem');
  const publicKeyFile = path.join(root, 'signing-public.pem');
  const privatePem = pair.privateKey.export({ format: 'pem', type: 'pkcs8' });
  const publicPem = pair.publicKey.export({ format: 'pem', type: 'spki' });
  writeSecret(dataKeyFile, dataKey);
  writeSecret(privateKeyFile, privatePem);
  fs.writeFileSync(publicKeyFile, publicPem);
  return {
    dataKey,
    dataKeyFile,
    privateKey: pair.privateKey,
    privateKeyFile,
    privatePem,
    publicKey: pair.publicKey,
    publicKeyFile
  };
};

const makeKeySnapshot = (root, keys, epoch) => {
  const suffix = String(epoch);
  const keyIdManifest = path.join(root, 'easr-v2-key-ids-' + suffix + '.json');
  build.generateKeyHeader({
    dataKeyFile: keys.dataKeyFile,
    signingPublicKeyFile: keys.publicKeyFile,
    minimumEpoch: suffix,
    output: path.join(root, 'easr-v2-key-material-' + suffix + '.h'),
    keyIdManifestOutput: keyIdManifest,
    trustWindowsKeyAcl
  });
  return keyIdManifest;
};

const readEnvelope = archive => {
  const bytes = fs.readFileSync(archive);
  const superblock = bytes.subarray(0, format.constants.SUPERBLOCK_SIZE);
  const parsed = format.parseSuperblock(superblock);
  const index = bytes.subarray(
    format.constants.SUPERBLOCK_SIZE,
    format.constants.SUPERBLOCK_SIZE + parsed.indexSize
  );
  return { bytes, index, parsed, superblock };
};

test('keeps all key roles explicit and rejects malformed GN arguments', () => {
  const parsed = gnEasr.parseArguments([
    '--base', 'base',
    '--files', 'base/a.js', 'base/b.js',
    '--out', 'app.asar',
    '--data-key-file', 'data.key',
    '--signing-private-key-file', 'private.pem',
    '--signing-public-key-file', 'public.pem',
    '--key-id-manifest', 'key-ids.json',
    '--epoch', '7',
    '--block-size-log2', '16',
    '--compression-level', '9',
    '--trust-windows-key-acl'
  ]);
  assert.deepStrictEqual(parsed.files, ['base/a.js', 'base/b.js']);
  assert.strictEqual(parsed.epoch, '7');
  assert.strictEqual(parsed.keyIdManifest, 'key-ids.json');
  assert.strictEqual(parsed.compressionLevel, 9);
  assert.strictEqual(parsed.trustWindowsKeyAcl, true);
  expectCode(() => gnEasr.parseArguments([
    '--base', 'one', '--base', 'two'
  ]), 'ERR_EASR_BUILD_ARGUMENT');
  assert.deepStrictEqual(keyHeader.parseArguments([
    '--data-key-file', 'data.key',
    '--signing-public-key-file', 'public.pem',
    '--minimum-epoch', '7',
    '--out', 'key.h',
    '--key-id-manifest-out', 'key-ids.json',
    '--trust-windows-key-acl'
  ]), {
    dataKeyFile: 'data.key',
    signingPublicKeyFile: 'public.pem',
    minimumEpoch: '7',
    output: 'key.h',
    keyIdManifestOutput: 'key-ids.json',
    trustWindowsKeyAcl: true
  });
});

test('generates only the data key and Ed25519 verification material', () =>
  withWorkspace(root => {
    const keys = makeKeyFiles(root);
    const output = path.join(root, 'generated', 'easr-key.h');
    const keyIdManifestOutput = path.join(
      root, 'generated', 'easr-key-ids.json');
    const result = build.generateKeyHeader({
      dataKeyFile: keys.dataKeyFile,
      signingPublicKeyFile: keys.publicKeyFile,
      minimumEpoch: '18446744073709551615',
      output,
      keyIdManifestOutput,
      trustWindowsKeyAcl
    });
    const header = fs.readFileSync(output, 'utf8');
    assert(header.includes('kMinimumEpoch = 18446744073709551615ULL'));
    assert(header.includes('class BuildKeyProvider final'));
    assert(header.includes('kDataKeyId'));
    assert(header.includes('kSigningPublicKey'));
    assert(!header.includes('-----BEGIN PRIVATE KEY-----'));
    assert(!header.includes(keys.privatePem.toString('base64')));
    const manifestText = fs.readFileSync(keyIdManifestOutput, 'utf8');
    assert(manifestText.length < 192);
    assert(!manifestText.includes(keys.dataKey.toString('hex')));
    assert.deepStrictEqual(JSON.parse(manifestText), {
      version: 1,
      dataKeyId: format.deriveDataKeyId(keys.dataKey).toString('hex'),
      signingKeyId: format.deriveSigningKeyId(keys.publicKey).toString('hex'),
      minimumEpoch: '18446744073709551615'
    });
    assert.strictEqual(result.dataKeyId,
      format.deriveDataKeyId(keys.dataKey).toString('hex'));
    assert.strictEqual(result.signingKeyId,
      format.deriveSigningKeyId(keys.publicKey).toString('hex'));
  }));

test('rejects a private key placed in the public verification role', () =>
  withWorkspace(root => {
    const keys = makeKeyFiles(root);
    expectCode(() => build.generateKeyHeader({
      dataKeyFile: keys.dataKeyFile,
      signingPublicKeyFile: keys.privateKeyFile,
      minimumEpoch: '1',
      output: path.join(root, 'bad.h'),
      keyIdManifestOutput: path.join(root, 'bad-key-ids.json'),
      trustWindowsKeyAcl
    }), 'ERR_EASR_BUILD_PUBLIC_KEY');
    assert(!fs.existsSync(path.join(root, 'bad.h')));
  }));

test('packs enumerated GN inputs, verifies key pairing, and replaces output', () =>
  withWorkspace(root => {
    const keys = makeKeyFiles(root);
    const source = path.join(root, 'source');
    const nested = path.join(source, 'nested');
    fs.mkdirSync(nested, { recursive: true });
    const entry = path.join(source, 'index.js');
    const selected = path.join(nested, 'selected.txt');
    const scrap = path.join(source, 'scrap.txt');
    fs.writeFileSync(entry, 'module.exports = 42;\n');
    fs.writeFileSync(selected, 'selected\n'.repeat(256));
    fs.writeFileSync(scrap, 'must not be packed');
    const output = path.join(root, 'app.asar');
    const keyIdManifest = makeKeySnapshot(root, keys, '9');
    const options = {
      base: source,
      files: [entry, selected],
      output,
      dataKeyFile: keys.dataKeyFile,
      signingPrivateKeyFile: keys.privateKeyFile,
      signingPublicKeyFile: keys.publicKeyFile,
      keyIdManifest,
      epoch: '9',
      blockSizeLog2: 16,
      compressionLevel: 9,
      compression: true,
      trustWindowsKeyAcl
    };
    build.packGnAsar(options);
    const first = readEnvelope(output);
    const verified = format.verifyEnvelope(first.superblock, first.index, {
      archiveSize: first.bytes.length,
      minimumEpoch: BigInt(9),
      resolveSigningKey: () => keys.publicKey
    });
    assert.deepStrictEqual(
      verified.index.entries.filter(item => item.type === 'file')
        .map(item => item.path),
      ['index.js', 'nested/selected.txt']
    );
    assert.strictEqual(verified.header.epoch, BigInt(9));

    fs.writeFileSync(entry, 'module.exports = 43;\n');
    build.packGnAsar(options);
    assert(!fs.readFileSync(output).equals(first.bytes));
  }));

test('fails before publication when private and public signing keys differ', () =>
  withWorkspace(root => {
    const keys = makeKeyFiles(root);
    const keyIdManifest = makeKeySnapshot(root, keys, '1');
    const other = crypto.generateKeyPairSync('ed25519');
    fs.writeFileSync(keys.publicKeyFile,
      other.publicKey.export({ format: 'pem', type: 'spki' }));
    const source = path.join(root, 'source');
    fs.mkdirSync(source);
    const input = path.join(source, 'index.js');
    fs.writeFileSync(input, 'ok\n');
    const output = path.join(root, 'bad.asar');
    expectCode(() => build.packGnAsar({
      base: source,
      files: [input],
      output,
      dataKeyFile: keys.dataKeyFile,
      signingPrivateKeyFile: keys.privateKeyFile,
      signingPublicKeyFile: keys.publicKeyFile,
      keyIdManifest,
      epoch: '1',
      trustWindowsKeyAcl
    }), 'ERR_EASR_BUILD_KEY_MISMATCH');
    assert(!fs.existsSync(output));
  }));

test('rejects data, signing, and epoch drift from the runtime key snapshot', () =>
  withWorkspace(root => {
    const keys = makeKeyFiles(root);
    const keyIdManifest = makeKeySnapshot(root, keys, '1');
    const source = path.join(root, 'source');
    fs.mkdirSync(source);
    const input = path.join(source, 'index.js');
    fs.writeFileSync(input, 'ok\n');
    const output = path.join(root, 'drifted.asar');
    const options = {
      base: source,
      files: [input],
      output,
      dataKeyFile: keys.dataKeyFile,
      signingPrivateKeyFile: keys.privateKeyFile,
      signingPublicKeyFile: keys.publicKeyFile,
      keyIdManifest,
      epoch: '2',
      trustWindowsKeyAcl
    };
    expectCode(() => build.packGnAsar(options),
      'ERR_EASR_BUILD_KEY_SNAPSHOT');

    options.epoch = '1';
    writeSecret(keys.dataKeyFile, Buffer.alloc(32, 0x7f));
    expectCode(() => build.packGnAsar(options),
      'ERR_EASR_BUILD_KEY_SNAPSHOT');

    writeSecret(keys.dataKeyFile, keys.dataKey);
    const other = crypto.generateKeyPairSync('ed25519');
    writeSecret(keys.privateKeyFile,
      other.privateKey.export({ format: 'pem', type: 'pkcs8' }));
    fs.writeFileSync(keys.publicKeyFile,
      other.publicKey.export({ format: 'pem', type: 'spki' }));
    expectCode(() => build.packGnAsar(options),
      'ERR_EASR_BUILD_KEY_SNAPSHOT');
    assert(!fs.existsSync(output));
  }));

test('rejects GN inputs that alias any build key', () =>
  withWorkspace(root => {
    const keys = makeKeyFiles(root);
    const keyIdManifest = makeKeySnapshot(root, keys, '1');
    const source = path.join(root, 'source');
    fs.mkdirSync(source);
    const input = path.join(source, 'index.js');
    const leaked = path.join(source, 'private-key-copy.pem');
    fs.writeFileSync(input, 'ok\n');
    fs.linkSync(keys.privateKeyFile, leaked);
    const output = path.join(root, 'leaked.asar');
    expectCode(() => build.packGnAsar({
      base: source,
      files: [input, leaked],
      output,
      dataKeyFile: keys.dataKeyFile,
      signingPrivateKeyFile: keys.privateKeyFile,
      signingPublicKeyFile: keys.publicKeyFile,
      keyIdManifest,
      epoch: '1',
      trustWindowsKeyAcl
    }), 'ERR_EASR_BUILD_KEY_IN_SOURCE');
    assert(!fs.existsSync(output));
  }));

test('hashes the fixed v2 header and validates its committed index', () =>
  withWorkspace(root => {
    const keys = makeKeyFiles(root);
    const keyIdManifest = makeKeySnapshot(root, keys, '3');
    const source = path.join(root, 'source');
    fs.mkdirSync(source);
    const input = path.join(source, 'index.js');
    fs.writeFileSync(input, 'module.exports = true;\n');
    const output = path.join(root, 'app.asar');
    build.packGnAsar({
      base: source,
      files: [input],
      output,
      dataKeyFile: keys.dataKeyFile,
      signingPrivateKeyFile: keys.privateKeyFile,
      signingPublicKeyFile: keys.publicKeyFile,
      keyIdManifest,
      epoch: '3',
      trustWindowsKeyAcl
    });
    const envelope = readEnvelope(output);
    const expected = crypto.createHash('sha256')
      .update(envelope.superblock)
      .digest('hex');
    assert.strictEqual(hash.hashAsarHeader(output), expected);

    const corrupted = path.join(root, 'corrupt.asar');
    const bytes = Buffer.from(envelope.bytes);
    bytes[format.constants.SUPERBLOCK_SIZE + 1] ^= 1;
    fs.writeFileSync(corrupted, bytes);
    assert.throws(() => hash.hashAsarHeader(corrupted),
      /signed index hash does not match/u);
  }));

test('preserves the ordinary ASAR header-hash contract', () =>
  withWorkspace(async root => {
    const source = path.join(root, 'source');
    fs.mkdirSync(source);
    fs.writeFileSync(path.join(source, 'index.js'), 'ordinary\n');
    const output = path.join(root, 'ordinary.asar');
    await asar.createPackage(source, output);
    const expected = crypto.createHash('sha256')
      .update(asar.getRawHeader(output).headerString)
      .digest('hex');
    assert.strictEqual(hash.hashAsarHeader(output), expected);
  }));

test('keeps default builds ordinary and excludes private keys from key header action', () => {
  const repository = path.resolve(__dirname, '..');
  const flags = fs.readFileSync(
    path.join(repository, 'buildflags', 'buildflags.gni'), 'utf8');
  const gn = fs.readFileSync(path.join(repository, 'build', 'asar.gni'), 'utf8');
  const rootBuild = fs.readFileSync(path.join(repository, 'BUILD.gn'), 'utf8');
  assert(/enable_easar_v2 = false/u.test(flags));
  assert(gn.includes('script = "//electron/script/gn-asar.js"'));
  assert(gn.includes('script = "//electron/script/gn-easar-v2.js"'));
  assert(gn.includes('deps += [ "//electron:easr_v2_key_material" ]'));
  assert(gn.includes('$root_gen_dir/electron/easr_v2_key_ids.json'));
  const action = rootBuild.slice(
    rootBuild.indexOf('node_action("easr_v2_key_material")'),
    rootBuild.indexOf('target_gen_default_app_js')
  );
  assert(action.includes('easar_v2_data_key_file'));
  assert(action.includes('easar_v2_signing_public_key_file'));
  assert(action.includes('easr_v2_key_ids.json'));
  assert(!action.includes('easar_v2_signing_private_key_file'));
  assert(!fs.existsSync(path.join(repository, 'script', 'easar-pack.js')));
});

(async () => {
  let failures = 0;
  for (const { name, body } of tests) {
    try {
      await body();
      process.stdout.write('ok - ' + name + '\n');
    } catch (error) {
      failures++;
      process.stderr.write('not ok - ' + name + '\n');
      process.stderr.write((error && error.stack) || String(error));
      process.stderr.write('\n');
    }
  }
  if (failures) process.exitCode = 1;
})();

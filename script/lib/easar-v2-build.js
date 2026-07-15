/* global BigInt */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const format = require('./easar-v2-format');

const DATA_KEY_MAX_BYTES = 128;
const SIGNING_KEY_MAX_BYTES = 16 * 1024;
const PUBLIC_KEY_MAX_BYTES = 16 * 1024;
const KEY_ID_MANIFEST_MAX_BYTES = 512;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

class EasrBuildError extends Error {
  constructor (code, message, cause) {
    super(message);
    this.name = 'EasrBuildError';
    this.code = code;
    if (cause) this.cause = cause;
  }
}

const fail = (code, message, cause) => {
  throw new EasrBuildError(code, message, cause);
};

const statIdentity = stat => ({
  dev: stat.dev,
  ino: stat.ino,
  mode: stat.mode,
  size: stat.size,
  mtimeNs: stat.mtimeNs,
  ctimeNs: stat.ctimeNs
});

const sameIdentity = (left, right) =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.mode === right.mode &&
  left.size === right.size &&
  left.mtimeNs === right.mtimeNs &&
  left.ctimeNs === right.ctimeNs;

// Build files are an explicit local trust boundary. Secret bytes never appear
// in argv, but the builder is responsible for protecting the configured paths.
// POSIX modes are enforceable here; pure Node cannot inspect Windows ACLs, so
// Windows callers must explicitly acknowledge their external ACL boundary.
const readStableFile = (filename, maximum, options = {}) => {
  let fd;
  try {
    const pathStat = fs.lstatSync(filename, { bigint: true });
    if (pathStat.isSymbolicLink()) {
      fail('ERR_EASR_BUILD_KEY_FILE', 'key path must not be a symbolic link');
    }
    const noFollow = fs.constants.O_NOFOLLOW || 0;
    fd = fs.openSync(filename, fs.constants.O_RDONLY | noFollow);
    const beforeStat = fs.fstatSync(fd, { bigint: true });
    const before = statIdentity(beforeStat);
    if (!sameIdentity(statIdentity(pathStat), before)) {
      fail('ERR_EASR_BUILD_KEY_FILE', 'key identity changed while opening');
    }
    if (!beforeStat.isFile()) {
      fail('ERR_EASR_BUILD_KEY_FILE', 'key path must name a regular file');
    }
    if (beforeStat.size > BigInt(maximum)) {
      fail('ERR_EASR_BUILD_KEY_FILE', 'key file exceeds its size limit');
    }
    if (options.secret && process.platform !== 'win32' &&
        (Number(beforeStat.mode) & 0o077) !== 0) {
      fail('ERR_EASR_BUILD_KEY_PERMISSIONS',
        'secret key file must not be accessible by group or other users');
    }
    if (options.secret && process.platform === 'win32' &&
        options.trustWindowsKeyAcl !== true) {
      fail('ERR_EASR_BUILD_KEY_PERMISSIONS',
        'Windows key ACL trust must be acknowledged explicitly');
    }
    const bytes = Buffer.alloc(Number(beforeStat.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, null);
      if (count <= 0) {
        bytes.fill(0);
        fail('ERR_EASR_BUILD_KEY_FILE', 'short read from key file');
      }
      offset += count;
    }
    const after = statIdentity(fs.fstatSync(fd, { bigint: true }));
    if (!sameIdentity(before, after)) {
      bytes.fill(0);
      fail('ERR_EASR_BUILD_KEY_FILE', 'key changed while it was read');
    }
    return bytes;
  } catch (error) {
    if (error instanceof EasrBuildError) throw error;
    fail('ERR_EASR_BUILD_KEY_FILE', 'failed to read key file', error);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
};

const loadBuildDataKey = (filename, options = {}) => {
  const bytes = readStableFile(filename, DATA_KEY_MAX_BYTES, {
    secret: true,
    trustWindowsKeyAcl: options.trustWindowsKeyAcl
  });
  try {
    let key;
    if (bytes.length === 32) {
      key = Buffer.from(bytes);
    } else {
      const text = bytes.toString('utf8').trim();
      if (!/^[0-9a-fA-F]{64}$/u.test(text)) {
        fail('ERR_EASR_BUILD_DATA_KEY',
          'data key must contain 32 raw bytes or 64 hex characters');
      }
      key = Buffer.from(text, 'hex');
    }
    if (!key.some(byte => byte !== 0)) {
      key.fill(0);
      fail('ERR_EASR_BUILD_DATA_KEY', 'data key must not be all zero');
    }
    return key;
  } finally {
    bytes.fill(0);
  }
};

const loadBuildPrivateKey = (filename, options = {}) => {
  const bytes = readStableFile(filename, SIGNING_KEY_MAX_BYTES, {
    secret: true,
    trustWindowsKeyAcl: options.trustWindowsKeyAcl
  });
  try {
    let key;
    const text = bytes.toString('ascii');
    if (text.includes('-----BEGIN')) {
      key = crypto.createPrivateKey(bytes);
    } else {
      key = crypto.createPrivateKey({
        key: bytes,
        format: 'der',
        type: 'pkcs8'
      });
    }
    if (key.asymmetricKeyType !== 'ed25519') {
      fail('ERR_EASR_BUILD_PRIVATE_KEY',
        'signing private key must be Ed25519');
    }
    return key;
  } catch (error) {
    if (error instanceof EasrBuildError) throw error;
    fail('ERR_EASR_BUILD_PRIVATE_KEY',
      'invalid Ed25519 signing private key', error);
  } finally {
    bytes.fill(0);
  }
};

const loadBuildPublicKey = filename => {
  const bytes = readStableFile(filename, PUBLIC_KEY_MAX_BYTES);
  try {
    let key;
    const text = bytes.toString('ascii');
    if (bytes.length === 32) {
      key = crypto.createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, bytes]),
        format: 'der',
        type: 'spki'
      });
    } else if (text.includes('-----BEGIN')) {
      if (!text.includes('-----BEGIN PUBLIC KEY-----') ||
          text.includes('PRIVATE KEY')) {
        fail('ERR_EASR_BUILD_PUBLIC_KEY',
          'verification key file must contain only a public key');
      }
      key = crypto.createPublicKey(bytes);
    } else {
      key = crypto.createPublicKey({
        key: bytes,
        format: 'der',
        type: 'spki'
      });
    }
    if (key.asymmetricKeyType !== 'ed25519') {
      fail('ERR_EASR_BUILD_PUBLIC_KEY',
        'verification public key must be Ed25519');
    }
    return key;
  } catch (error) {
    if (error instanceof EasrBuildError) throw error;
    fail('ERR_EASR_BUILD_PUBLIC_KEY',
      'invalid Ed25519 verification public key', error);
  } finally {
    bytes.fill(0);
  }
};

const rawEd25519PublicKey = publicKey => {
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  if (spki.length !== ED25519_SPKI_PREFIX.length + 32 ||
      !spki.subarray(0, ED25519_SPKI_PREFIX.length)
        .equals(ED25519_SPKI_PREFIX)) {
    fail('ERR_EASR_BUILD_PUBLIC_KEY',
      'verification key has a non-canonical Ed25519 encoding');
  }
  return Buffer.from(spki.subarray(ED25519_SPKI_PREFIX.length));
};

const parseEpoch = value => {
  if (typeof value !== 'string' || !/^[0-9]+$/u.test(value)) {
    fail('ERR_EASR_BUILD_EPOCH', 'minimum epoch must be an unsigned decimal');
  }
  const epoch = BigInt(value);
  if (epoch > format.constants.UINT64_MAX) {
    fail('ERR_EASR_BUILD_EPOCH', 'minimum epoch exceeds uint64');
  }
  return epoch;
};

const renderKeyIdManifest = ({ dataKeyId, signingKeyId, minimumEpoch }) =>
  JSON.stringify({
    version: 1,
    dataKeyId: dataKeyId.toString('hex'),
    signingKeyId: signingKeyId.toString('hex'),
    minimumEpoch: minimumEpoch.toString()
  }) + '\n';

const loadKeyIdManifest = filename => {
  let bytes;
  try {
    bytes = readStableFile(filename, KEY_ID_MANIFEST_MAX_BYTES);
  } catch (error) {
    fail('ERR_EASR_BUILD_KEY_MANIFEST',
      'failed to read key ID manifest', error);
  }
  try {
    const manifest = JSON.parse(bytes.toString('utf8'));
    const expectedKeys = [
      'dataKeyId',
      'minimumEpoch',
      'signingKeyId',
      'version'
    ];
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest) ||
        Object.keys(manifest).sort().join('\0') !== expectedKeys.join('\0') ||
        manifest.version !== 1 ||
        typeof manifest.dataKeyId !== 'string' ||
        !/^[0-9a-f]{32}$/u.test(manifest.dataKeyId) ||
        typeof manifest.signingKeyId !== 'string' ||
        !/^[0-9a-f]{32}$/u.test(manifest.signingKeyId) ||
        typeof manifest.minimumEpoch !== 'string' ||
        !/^(?:0|[1-9][0-9]*)$/u.test(manifest.minimumEpoch)) {
      fail('ERR_EASR_BUILD_KEY_MANIFEST',
        'key ID manifest has an invalid schema');
    }
    const minimumEpoch = BigInt(manifest.minimumEpoch);
    if (minimumEpoch > format.constants.UINT64_MAX) {
      fail('ERR_EASR_BUILD_KEY_MANIFEST',
        'key ID manifest epoch exceeds uint64');
    }
    return {
      dataKeyId: Buffer.from(manifest.dataKeyId, 'hex'),
      signingKeyId: Buffer.from(manifest.signingKeyId, 'hex'),
      minimumEpoch
    };
  } catch (error) {
    if (error instanceof EasrBuildError) throw error;
    fail('ERR_EASR_BUILD_KEY_MANIFEST',
      'invalid key ID manifest', error);
  } finally {
    bytes.fill(0);
  }
};

const byteArray = (name, bytes) => {
  const rows = [];
  for (let offset = 0; offset < bytes.length; offset += 8) {
    rows.push('    ' + Array.from(bytes.subarray(offset, offset + 8))
      .map(byte => '0x' + byte.toString(16).padStart(2, '0'))
      .join(', '));
  }
  return '  inline static constexpr std::array<uint8_t, ' + bytes.length +
    '> ' + name + ' = {\n' + rows.join(',\n') + '\n  };';
};

const renderKeyHeader = ({ dataKey, publicKey, minimumEpoch }) => {
  const dataKeyId = format.deriveDataKeyId(dataKey);
  const signingKeyId = format.deriveSigningKeyId(publicKey);
  const rawPublicKey = rawEd25519PublicKey(publicKey);
  return [
    '// Generated by generate-easar-v2-key-header.js. Do not edit.',
    '// This file contains the runtime decryption key and verification public',
    '// key. It never contains the signing private key.',
    '#ifndef ELECTRON_GEN_EASR_V2_KEY_MATERIAL_H_',
    '#define ELECTRON_GEN_EASR_V2_KEY_MATERIAL_H_',
    '',
    '#include <array>',
    '#include <cstdint>',
    '',
    '#include "shell/common/asar/archive.h"',
    '',
    'namespace electron::easr_v2_build {',
    '',
    'class BuildKeyProvider final : public asar::EasrKeyProvider {',
    ' public:',
    '  bool GetDataKey(const asar::EasrKeyId& id,',
    '                  std::array<uint8_t, 32>* key) const override {',
    '    if (!key || id != kDataKeyId)',
    '      return false;',
    '    *key = kDataKey;',
    '    return true;',
    '  }',
    '',
    '  bool GetSigningPublicKey(',
    '      const asar::EasrKeyId& id,',
    '      std::array<uint8_t, 32>* public_key) const override {',
    '    if (!public_key || id != kSigningKeyId)',
    '      return false;',
    '    *public_key = kSigningPublicKey;',
    '    return true;',
    '  }',
    '',
    '  uint64_t GetMinimumEpoch(',
    '      const asar::EasrKeyId& data_key_id,',
    '      const asar::EasrKeyId& signing_key_id) const override {',
    '    return data_key_id == kDataKeyId && signing_key_id == kSigningKeyId',
    '               ? kMinimumEpoch',
    '               : 0;',
    '  }',
    '',
    ' private:',
    byteArray('kDataKeyId', dataKeyId),
    byteArray('kSigningKeyId', signingKeyId),
    byteArray('kDataKey', dataKey),
    byteArray('kSigningPublicKey', rawPublicKey),
    '  inline static constexpr uint64_t kMinimumEpoch = ' +
      minimumEpoch.toString() + 'ULL;',
    '};',
    '',
    'inline const BuildKeyProvider kBuildKeyProvider;',
    '',
    'inline const asar::EasrKeyProvider* GetKeyProvider() {',
    '  return &kBuildKeyProvider;',
    '}',
    '',
    '}  // namespace electron::easr_v2_build',
    '',
    '#endif  // ELECTRON_GEN_EASR_V2_KEY_MATERIAL_H_',
    ''
  ].join('\n');
};

const replaceFile = (temporary, output) => {
  try {
    fs.renameSync(temporary, output);
  } catch (error) {
    if (!fs.existsSync(output)) throw error;
    fs.unlinkSync(output);
    fs.renameSync(temporary, output);
  }
};

const writeFileAtomically = (output, contents, mode) => {
  const resolved = path.resolve(output);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  const temporary = path.join(
    path.dirname(resolved),
    '.' + path.basename(resolved) + '.' + process.pid + '.' +
      crypto.randomBytes(8).toString('hex') + '.tmp'
  );
  try {
    fs.writeFileSync(temporary, contents, { flag: 'wx', mode });
    replaceFile(temporary, resolved);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
};

const generateKeyHeader = options => {
  if (!options || !options.dataKeyFile || !options.signingPublicKeyFile ||
      !options.output || !options.keyIdManifestOutput) {
    fail('ERR_EASR_BUILD_ARGUMENT',
      'data key, signing public key, epoch, header output, and key ID ' +
      'manifest output are required');
  }
  const minimumEpoch = parseEpoch(options.minimumEpoch);
  const dataKey = loadBuildDataKey(options.dataKeyFile, options);
  try {
    const publicKey = loadBuildPublicKey(options.signingPublicKeyFile);
    const dataKeyId = format.deriveDataKeyId(dataKey);
    const signingKeyId = format.deriveSigningKeyId(publicKey);
    const header = renderKeyHeader({ dataKey, publicKey, minimumEpoch });
    const manifest = renderKeyIdManifest({
      dataKeyId,
      signingKeyId,
      minimumEpoch
    });
    writeFileAtomically(options.output, header, 0o600);
    writeFileAtomically(options.keyIdManifestOutput, manifest, 0o600);
    return {
      dataKeyId: dataKeyId.toString('hex'),
      signingKeyId: signingKeyId.toString('hex'),
      minimumEpoch: minimumEpoch.toString()
    };
  } finally {
    dataKey.fill(0);
  }
};

const relativeGnInput = (base, input) => {
  const relative = path.relative(base, input);
  if (!relative || relative === '..' || relative.startsWith('..' + path.sep) ||
      path.isAbsolute(relative)) {
    fail('ERR_EASR_BUILD_INPUT',
      'every GN input must be a file strictly inside the base directory');
  }
  return relative;
};

const fileIdentity = filename => {
  const stat = fs.statSync(filename, { bigint: true });
  return stat.dev.toString() + ':' + stat.ino.toString();
};

const copyStableGnInput = (input, output, pathStat, forbiddenIdentities) => {
  const buffer = Buffer.allocUnsafe(64 * 1024);
  let sourceFd;
  let destinationFd;
  try {
    const noFollow = fs.constants.O_NOFOLLOW || 0;
    sourceFd = fs.openSync(input, fs.constants.O_RDONLY | noFollow);
    const beforeStat = fs.fstatSync(sourceFd, { bigint: true });
    const before = statIdentity(beforeStat);
    if (!beforeStat.isFile() ||
        !sameIdentity(statIdentity(pathStat), before)) {
      fail('ERR_EASR_BUILD_INPUT',
        'GN input identity changed while opening: ' + input);
    }
    if (beforeStat.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail('ERR_EASR_BUILD_INPUT', 'GN input is too large: ' + input);
    }
    const sourceSize = Number(beforeStat.size);
    const identity = beforeStat.dev.toString() + ':' +
      beforeStat.ino.toString();
    if (forbiddenIdentities.has(identity)) {
      fail('ERR_EASR_BUILD_KEY_IN_SOURCE',
        'GN inputs must not contain data or signing key files');
    }

    destinationFd = fs.openSync(output, 'wx', 0o600);
    const copiedHash = crypto.createHash('sha256');
    let position = 0;
    while (position < sourceSize) {
      const count = fs.readSync(sourceFd, buffer, 0,
        Math.min(buffer.length, sourceSize - position), position);
      if (count <= 0) {
        fail('ERR_EASR_BUILD_INPUT', 'short read from GN input: ' + input);
      }
      copiedHash.update(buffer.subarray(0, count));
      let written = 0;
      while (written < count) {
        const result = fs.writeSync(destinationFd, buffer, written,
          count - written, null);
        if (result <= 0) {
          fail('ERR_EASR_BUILD_INPUT',
            'short write while staging GN input: ' + input);
        }
        written += result;
      }
      position += count;
    }
    fs.fchmodSync(destinationFd, Number(beforeStat.mode) & 0o777);

    const verifiedHash = crypto.createHash('sha256');
    position = 0;
    while (position < sourceSize) {
      const count = fs.readSync(sourceFd, buffer, 0,
        Math.min(buffer.length, sourceSize - position), position);
      if (count <= 0) {
        fail('ERR_EASR_BUILD_INPUT',
          'short verification read from GN input: ' + input);
      }
      verifiedHash.update(buffer.subarray(0, count));
      position += count;
    }
    const after = statIdentity(fs.fstatSync(sourceFd, { bigint: true }));
    const pathAfter = statIdentity(fs.lstatSync(input, { bigint: true }));
    if (!sameIdentity(before, after) || !sameIdentity(before, pathAfter) ||
        !crypto.timingSafeEqual(copiedHash.digest(),
          verifiedHash.digest())) {
      fail('ERR_EASR_BUILD_INPUT',
        'GN input changed while it was staged: ' + input);
    }
  } finally {
    buffer.fill(0);
    if (destinationFd !== undefined) fs.closeSync(destinationFd);
    if (sourceFd !== undefined) fs.closeSync(sourceFd);
  }
};

const stageGnInputs = (basePath, files, destination,
  forbiddenIdentities = new Set()) => {
  const base = fs.realpathSync(path.resolve(basePath));
  if (!fs.statSync(base).isDirectory()) {
    fail('ERR_EASR_BUILD_INPUT', 'GN base must be a directory');
  }
  if (!Array.isArray(files) || files.length === 0) {
    fail('ERR_EASR_BUILD_INPUT', 'at least one GN input is required');
  }
  const seen = new Set();
  for (const filename of files) {
    const input = path.resolve(filename);
    const relative = relativeGnInput(base, input);
    const portable = relative.split(path.sep).join('/');
    if (seen.has(portable)) {
      fail('ERR_EASR_BUILD_INPUT', 'duplicate GN input: ' + portable);
    }
    seen.add(portable);
    const stat = fs.lstatSync(input, { bigint: true });
    if (!stat.isFile()) {
      fail('ERR_EASR_BUILD_INPUT', 'GN input must be a regular file');
    }
    const output = path.join(destination, relative);
    fs.mkdirSync(path.dirname(output), { recursive: true });
    copyStableGnInput(input, output, stat, forbiddenIdentities);
  }
};

const packGnAsar = options => {
  if (!options || !options.base || !options.output ||
      !options.dataKeyFile || !options.signingPrivateKeyFile ||
      !options.signingPublicKeyFile || !options.keyIdManifest) {
    fail('ERR_EASR_BUILD_ARGUMENT',
      'GN inputs, output, all three key roles, and the key ID manifest are ' +
      'required');
  }
  const epoch = parseEpoch(options.epoch);
  // Keep key-header generation light: the streaming packer is loaded only by
  // the archive action, never by the runtime-material action.
  const packer = require('./easar-v2-packer');
  const dataKey = loadBuildDataKey(options.dataKeyFile, options);
  let temporaryOutput;
  let stagingRoot;
  try {
    const privateKey = loadBuildPrivateKey(options.signingPrivateKeyFile,
      options);
    const publicKey = loadBuildPublicKey(options.signingPublicKeyFile);
    const privateId = format.deriveSigningKeyId(privateKey);
    const publicId = format.deriveSigningKeyId(publicKey);
    if (!crypto.timingSafeEqual(privateId, publicId)) {
      fail('ERR_EASR_BUILD_KEY_MISMATCH',
        'signing private key does not match verification public key');
    }
    const snapshot = loadKeyIdManifest(options.keyIdManifest);
    const dataKeyId = format.deriveDataKeyId(dataKey);
    if (epoch !== snapshot.minimumEpoch ||
        !crypto.timingSafeEqual(dataKeyId, snapshot.dataKeyId) ||
        !crypto.timingSafeEqual(publicId, snapshot.signingKeyId)) {
      fail('ERR_EASR_BUILD_KEY_SNAPSHOT',
        'build keys or epoch changed after runtime key material generation');
    }
    const forbiddenIdentities = new Set([
      fileIdentity(options.dataKeyFile),
      fileIdentity(options.signingPrivateKeyFile),
      fileIdentity(options.signingPublicKeyFile)
    ]);
    const output = path.resolve(options.output);
    const outputDirectory = path.dirname(output);
    fs.mkdirSync(outputDirectory, { recursive: true });
    packer.preflightCapabilities(outputDirectory, {
      trustWindowsOutputAcl: options.trustWindowsKeyAcl === true
    });
    // Keep staging inside the same trusted directory boundary as the signed
    // output. On Windows, os.tmpdir() can inherit a shared DACL that lets a
    // local process replace inputs before the packer establishes its baseline.
    stagingRoot = fs.mkdtempSync(
      path.join(outputDirectory, '.electron-gn-easr-'));
    fs.chmodSync(stagingRoot, 0o700);
    stageGnInputs(options.base, options.files, stagingRoot,
      forbiddenIdentities);

    temporaryOutput = path.join(
      outputDirectory,
      '.' + path.basename(output) + '.' + process.pid + '.' +
        crypto.randomBytes(8).toString('hex') + '.easr.tmp'
    );
    const result = packer.requireCleanCliResult(packer.packArchive({
      source: stagingRoot,
      output: temporaryOutput,
      dataKey,
      signingPrivateKey: privateKey,
      signingKeyId: publicId,
      epoch,
      blockSizeLog2: options.blockSizeLog2,
      compressionLevel: options.compressionLevel,
      compression: options.compression !== false,
      trustWindowsOutputAcl: options.trustWindowsKeyAcl === true
    }));
    replaceFile(temporaryOutput, output);
    temporaryOutput = undefined;
    return result;
  } finally {
    dataKey.fill(0);
    if (temporaryOutput) fs.rmSync(temporaryOutput, { force: true });
    if (stagingRoot) {
      fs.rmSync(stagingRoot, { recursive: true, force: true });
    }
  }
};

module.exports = {
  EasrBuildError,
  generateKeyHeader,
  loadBuildDataKey,
  loadBuildPrivateKey,
  loadBuildPublicKey,
  packGnAsar,
  parseEpoch,
  rawEd25519PublicKey,
  renderKeyHeader,
  stageGnInputs
};

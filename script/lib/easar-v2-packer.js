/* global BigInt */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const format = require('./easar-v2-format');

const DEFAULT_BLOCK_SIZE_LOG2 = 16;
const DEFAULT_COMPRESSION_LEVEL = 6;
const TEMP_PREFIX = '.easar-v2-';
const DATA_KEY_MAX_BYTES = 128;
const SIGNING_KEY_MAX_BYTES = 16 * 1024;
const UNPACK_LIST_MAX_BYTES = 1024 * 1024;
const ENTROPY_SKIP_THRESHOLD = 7.75;
const SMALL_FILE_DIRECT_COMPRESSION_MAX = 256 * 1024;
const READ_NOFOLLOW = fs.constants.O_RDONLY |
  (fs.constants.O_NOFOLLOW || 0);

const COMPRESSIBLE_EXTENSIONS = new Set([
  '.cjs', '.css', '.csv', '.htm', '.html', '.js', '.json', '.map', '.md',
  '.mjs', '.svg', '.text', '.toml', '.ts', '.tsx', '.txt', '.xml', '.yaml',
  '.yml'
]);
const INCOMPRESSIBLE_EXTENSIONS = new Set([
  '.7z', '.avi', '.br', '.bz2', '.gif', '.gz', '.ico', '.jpeg',
  '.jpg', '.m4a', '.mkv', '.mov', '.mp3', '.mp4', '.ogg', '.otf',
  '.pdf', '.png', '.rar', '.ttf', '.webm', '.webp', '.woff', '.woff2',
  '.xz', '.zip'
]);
const MUTATION_HOOK_NAMES = Object.freeze([
  'beforeEncrypt',
  'beforeSourceRevalidate',
  'beforeCommit',
  'afterSidecarPublish'
]);
const capabilityCache = new Map();

const PLATFORM_CONTRACT = Object.freeze({
  publicationRequirement: 'same-volume-hard-link-create-if-absent',
  unsafePublicationFallback: false,
  keyFileAclVerification: process.platform === 'win32'
    ? 'unavailable-fail-closed'
    : 'posix-mode-mask-enforced',
  outputDirectoryAclVerification: process.platform === 'win32'
    ? 'unavailable-fail-closed-with-explicit-trust'
    : 'owner-mode-and-sticky-ancestor-enforced',
  extendedAclBoundary: process.platform === 'win32'
    ? 'pure Node cannot inspect Windows ACLs; use programmatic key material'
    : 'mode 0600 forces the POSIX ACL group-class mask to zero',
  crashBoundary:
    'archive is linked last; an archive-absent .unpacked tree is removable'
});

class EasrPackerError extends Error {
  constructor (code, message, cause) {
    super(message);
    this.name = 'EasrPackerError';
    this.code = code;
    if (cause) this.cause = cause;
  }
}

const fail = (code, message, cause) => {
  throw new EasrPackerError(code, message, cause);
};

const capabilityFailure = (code, message, capability, cause) => {
  const error = new EasrPackerError(code, message, cause);
  error.capability = capability;
  error.platformContract = PLATFORM_CONTRACT;
  throw error;
};

const getPlatformContract = () => PLATFORM_CONTRACT;

const preflightCapabilities = (outputParent, options = {}) => {
  let parent;
  try {
    parent = fs.realpathSync(path.resolve(outputParent));
  } catch (error) {
    capabilityFailure(
      'ERR_EASR_CAPABILITY_PATH',
      'capability output directory does not exist',
      'output-directory',
      error
    );
  }
  const outputBoundary = validateOutputBoundary(parent, options);
  if (!options.force && capabilityCache.has(parent)) {
    return Object.freeze({
      ...capabilityCache.get(parent),
      outputBoundary
    });
  }

  let probeDirectory;
  let sourceFd;
  let probeError;
  let cleanupError;
  try {
    probeDirectory = fs.mkdtempSync(
      path.join(parent, '.easar-v2-capability-')
    );
    const source = path.join(probeDirectory, 'source');
    const linked = path.join(probeDirectory, 'linked');
    sourceFd = fs.openSync(source, 'wx', 0o600);
    writeAll(sourceFd, Buffer.from([0xa5]));
    fs.fsyncSync(sourceFd);
    safeClose(sourceFd);
    sourceFd = null;
    fs.linkSync(source, linked);
    const sourceStat = fs.statSync(source, { bigint: true });
    const linkedStat = fs.statSync(linked, { bigint: true });
    if (sourceStat.dev !== linkedStat.dev || sourceStat.ino !== linkedStat.ino ||
        !fs.readFileSync(linked).equals(Buffer.from([0xa5]))) {
      throw new Error('hard-link identity verification failed');
    }
    let collisionRejected = false;
    try {
      fs.linkSync(source, linked);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      collisionRejected = true;
    }
    if (!collisionRejected) {
      throw new Error('hard-link collision did not fail closed');
    }
  } catch (error) {
    probeError = error;
  } finally {
    safeClose(sourceFd);
    if (probeDirectory) {
      for (const name of ['linked', 'source']) {
        const filename = path.join(probeDirectory, name);
        try {
          fs.unlinkSync(filename);
        } catch (error) {
          if (error.code !== 'ENOENT' && !cleanupError) {
            cleanupError = error;
          }
        }
      }
      try {
        fs.rmdirSync(probeDirectory);
      } catch (error) {
        if (!cleanupError) cleanupError = error;
      }
    }
  }
  if (cleanupError) {
    capabilityFailure(
      'ERR_EASR_CAPABILITY_CLEANUP',
      'hard-link capability probe left a residual path: ' + probeDirectory,
      'capability-probe-cleanup',
      cleanupError
    );
  }
  if (probeError) {
    capabilityFailure(
      'ERR_EASR_CAPABILITY_HARDLINK',
      'output filesystem lacks atomic hard-link create-if-absent support',
      'same-volume-hard-link-create-if-absent',
      probeError
    );
  }
  const result = Object.freeze({
    outputParent: parent,
    atomicNoClobberPublication: true,
    keyFileAclVerification: PLATFORM_CONTRACT.keyFileAclVerification,
    unsafeFallback: false
  });
  capabilityCache.set(parent, result);
  return Object.freeze({ ...result, outputBoundary });
};

const requireBuffer = (value, size, name, code = 'ERR_EASR_PACK_FIELD') => {
  if (!Buffer.isBuffer(value) || value.length !== size) {
    fail(code, name + ' must be exactly ' + size + ' bytes');
  }
  return value;
};

const requireNonZeroBuffer = (value, size, name) => {
  requireBuffer(value, size, name);
  if (!value.some(byte => byte !== 0)) {
    fail('ERR_EASR_PACK_FIELD', name + ' must not be all zero');
  }
  return value;
};

const asSigningPrivateKey = value => {
  let key;
  try {
    key = value && value.type === 'private'
      ? value
      : crypto.createPrivateKey(value);
  } catch (error) {
    fail('ERR_EASR_SIGNING_KEY', 'invalid signing private key file', error);
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    fail('ERR_EASR_SIGNING_KEY', 'signing key must be Ed25519');
  }
  return key;
};

const isWithin = (parent, candidate) => {
  const relative = path.relative(parent, candidate);
  return relative === '' ||
    (!path.isAbsolute(relative) &&
      relative !== '..' &&
      !relative.startsWith('..' + path.sep));
};

const toArchivePath = (root, absolute) =>
  path.relative(root, absolute).split(path.sep).join('/');

const statSnapshot = stat => ({
  dev: stat.dev.toString(),
  ino: stat.ino.toString(),
  mode: stat.mode.toString(),
  size: stat.size.toString(),
  mtimeNs: stat.mtimeNs
    ? stat.mtimeNs.toString()
    : String(Math.round(Number(stat.mtimeMs) * 1000000)),
  ctimeNs: stat.ctimeNs
    ? stat.ctimeNs.toString()
    : String(Math.round(Number(stat.ctimeMs) * 1000000))
});

const sameSnapshot = (left, right) =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.mode === right.mode &&
  left.size === right.size &&
  left.mtimeNs === right.mtimeNs &&
  left.ctimeNs === right.ctimeNs;

const sameIdentity = (left, right) =>
  left.dev === right.dev && left.ino === right.ino;

const validateOutputBoundary = (outputParent, options = {}) => {
  const parent = path.resolve(outputParent);
  let parentStat;
  try {
    parentStat = fs.lstatSync(parent, { bigint: true });
  } catch (error) {
    capabilityFailure(
      'ERR_EASR_OUTPUT_BOUNDARY',
      'output directory identity could not be verified',
      'trusted-output-directory',
      error
    );
  }
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) {
    capabilityFailure(
      'ERR_EASR_OUTPUT_BOUNDARY',
      'output path must resolve to a physical directory',
      'trusted-output-directory'
    );
  }

  if (process.platform === 'win32') {
    if (options.trustWindowsOutputAcl !== true) {
      capabilityFailure(
        'ERR_EASR_OUTPUT_ACL_UNVERIFIABLE',
        'pure Node cannot verify the Windows output-directory DACL; ' +
          'pass explicit trust only for a separately secured directory',
        'trusted-output-directory'
      );
    }
    return Object.freeze({
      parent,
      snapshot: Object.freeze(statSnapshot(parentStat)),
      windowsAclTrusted: true
    });
  }

  if (typeof process.geteuid === 'function') {
    const effectiveUid = process.geteuid();
    let current = parent;
    let childStat;
    let isOutputParent = true;
    while (true) {
      const stat = isOutputParent
        ? parentStat
        : fs.lstatSync(current, { bigint: true });
      if (!stat.isDirectory() || stat.isSymbolicLink()) {
        capabilityFailure(
          'ERR_EASR_OUTPUT_BOUNDARY',
          'output ancestor is not a physical directory: ' + current,
          'trusted-output-directory'
        );
      }
      const mode = Number(stat.mode) & 0o7777;
      if (isOutputParent) {
        if (Number(stat.uid) !== effectiveUid || (mode & 0o022) !== 0) {
          capabilityFailure(
            'ERR_EASR_OUTPUT_ACL',
            'output directory must be owned by the current user and not ' +
              'group/world writable',
            'trusted-output-directory'
          );
        }
      } else if ((mode & 0o022) !== 0 &&
                 ((mode & 0o1000) === 0 ||
                  !childStat || Number(childStat.uid) !== effectiveUid)) {
        capabilityFailure(
          'ERR_EASR_OUTPUT_ACL',
          'writable output ancestor lacks sticky ownership protection: ' +
            current,
          'trusted-output-directory'
        );
      }
      childStat = stat;
      const next = path.dirname(current);
      if (next === current) break;
      current = next;
      isOutputParent = false;
    }
  }

  return Object.freeze({
    parent,
    snapshot: Object.freeze(statSnapshot(parentStat)),
    windowsAclTrusted: false
  });
};

const revalidateOutputBoundary = (expected, options = {}) => {
  const current = validateOutputBoundary(expected.parent, options);
  if (!sameIdentity(current.snapshot, expected.snapshot)) {
    capabilityFailure(
      'ERR_EASR_OUTPUT_BOUNDARY_CHANGED',
      'output directory identity changed during packing',
      'trusted-output-directory'
    );
  }
  return current;
};

const sourceIdentity = stat => stat.dev.toString() + ':' + stat.ino.toString();

const safeClose = fd => {
  if (fd === null || fd === undefined) return;
  try {
    fs.closeSync(fd);
  } catch (error) {
    // Cleanup must never replace the operation's primary result.
  }
};

const safeRemove = (target, options = {}) => {
  try {
    fs.rmSync(target, { force: true, ...options });
    return null;
  } catch (error) {
    // A failed cleanup leaves a private, uniquely named recovery artifact.
    return error;
  }
};

const safeUnlink = target => safeRemove(target);

const safeSyncDirectory = directory => {
  if (process.platform === 'win32') return;
  let fd;
  try {
    fd = fs.openSync(
      directory,
      fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0)
    );
    fs.fsyncSync(fd);
  } catch (error) {
    // Directory fsync is not portable; file fsync and atomic links remain.
  } finally {
    safeClose(fd);
  }
};

const publishedMode = executable =>
  (executable ? 0o755 : 0o644) & ~process.umask();

const readBoundedFd = (fd, maximum, code, description) => {
  const parts = [];
  let total = 0;
  const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, maximum + 1));
  try {
    while (true) {
      const count = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (count === 0) break;
      total += count;
      if (total > maximum) {
        fail(code, description + ' exceeds ' + maximum + ' bytes');
      }
      parts.push(Buffer.from(buffer.subarray(0, count)));
    }
    return Buffer.concat(parts, total);
  } finally {
    buffer.fill(0);
    for (const part of parts) part.fill(0);
  }
};

const normalizeSymlinkTarget = (sourceRoot, linkPath, rawTarget) => {
  if (typeof rawTarget !== 'string' || rawTarget.length === 0 ||
      path.isAbsolute(rawTarget) || path.win32.isAbsolute(rawTarget)) {
    fail('ERR_EASR_SYMLINK', 'symlink target must be relative');
  }
  const resolved = path.resolve(path.dirname(linkPath), rawTarget);
  if (!isWithin(sourceRoot, resolved) || resolved === sourceRoot) {
    fail('ERR_EASR_SYMLINK', 'symlink target escapes the source root');
  }
  return toArchivePath(sourceRoot, resolved);
};

const scanSource = sourceRoot => {
  const sortableInventory = [];
  let expandedPathBytes = 0;
  const addInventoryItem = item => {
    if (sortableInventory.length >= format.constants.MAX_ENTRY_COUNT) {
      fail('ERR_EASR_ENTRY_LIMIT', 'too many index entries');
    }
    const pathBytes = Buffer.from(item.path, 'utf8');
    if (expandedPathBytes >
        format.constants.MAX_EXPANDED_PATH_BYTES - pathBytes.length) {
      fail('ERR_EASR_EXPANDED_PATH_LIMIT',
        'expanded index paths exceed their strict byte limit');
    }
    expandedPathBytes += pathBytes.length;
    sortableInventory.push({ item, pathBytes });
  };
  const pathIdentity = value => {
    const resolved = path.resolve(value);
    return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
  };
  const visit = (directory, expectedSnapshot) => {
    const beforeStat = fs.lstatSync(directory, { bigint: true });
    const before = statSnapshot(beforeStat);
    if (!beforeStat.isDirectory() ||
        (expectedSnapshot && !sameSnapshot(before, expectedSnapshot))) {
      fail('ERR_EASR_SOURCE_CHANGED',
        'source directory identity changed during traversal');
    }
    const nativeRealpath = fs.realpathSync.native || fs.realpathSync;
    if (pathIdentity(nativeRealpath(directory)) !== pathIdentity(directory)) {
      fail('ERR_EASR_FILE_TYPE',
        'directory reparse points outside the physical source tree');
    }
    const names = fs.readdirSync(directory);
    for (const name of names) {
      const absolute = path.join(directory, name);
      const stat = fs.lstatSync(absolute, { bigint: true });
      const relativePath = toArchivePath(sourceRoot, absolute);
      const common = {
        absolute,
        path: relativePath,
        snapshot: statSnapshot(stat),
        mode: Number(stat.mode)
      };
      if (stat.isDirectory()) {
        addInventoryItem({ ...common, type: 'directory' });
        visit(absolute, common.snapshot);
      } else if (stat.isFile()) {
        const size = Number(stat.size);
        if (!Number.isSafeInteger(size)) {
          fail('ERR_EASR_FILE_SIZE', 'source file is too large');
        }
        addInventoryItem({ ...common, type: 'file', size });
      } else if (stat.isSymbolicLink()) {
        const rawTarget = fs.readlinkSync(absolute, 'utf8');
        addInventoryItem({
          ...common,
          type: 'symlink',
          rawTarget,
          target: normalizeSymlinkTarget(sourceRoot, absolute, rawTarget)
        });
      } else {
        fail('ERR_EASR_FILE_TYPE',
          'unsupported source entry type: ' + relativePath);
      }
    }
    const after = statSnapshot(fs.lstatSync(directory, { bigint: true }));
    if (!sameSnapshot(before, after)) {
      fail('ERR_EASR_SOURCE_CHANGED',
        'source directory changed during traversal');
    }
  };
  visit(sourceRoot);
  // Cache each UTF-8 key once for sorting. Creating both keys in every sort
  // comparison turns large inventories into allocation-heavy O(n log n) work.
  sortableInventory.sort((left, right) =>
    Buffer.compare(left.pathBytes, right.pathBytes));
  return sortableInventory.map(value => value.item);
};

const validationEntries = (inventory, unpack) => inventory.map(item => {
  if (item.type === 'directory') {
    return { path: item.path, type: 'directory' };
  }
  if (item.type === 'symlink') {
    return { path: item.path, type: 'symlink', target: item.target };
  }
  return {
    path: item.path,
    type: 'file',
    unpacked: true,
    executable: (item.mode & 0o111) !== 0,
    size: item.size,
    digest: Buffer.alloc(32)
  };
});

const assertInventoryMatches = (expected, actual) => {
  if (expected.length !== actual.length) {
    fail('ERR_EASR_SOURCE_CHANGED',
      'source inventory changed during packing');
  }
  for (let index = 0; index < expected.length; index++) {
    const left = expected[index];
    const right = actual[index];
    if (left.path !== right.path || left.type !== right.type ||
        !sameSnapshot(left.snapshot, right.snapshot) ||
        left.target !== right.target) {
      fail('ERR_EASR_SOURCE_CHANGED',
        'source entry changed during packing: ' + left.path);
    }
  }
};

const writeAll = (fd, buffer, position = null) => {
  let written = 0;
  while (written < buffer.length) {
    const count = fs.writeSync(
      fd,
      buffer,
      written,
      buffer.length - written,
      position === null ? null : position + written
    );
    if (count <= 0) fail('ERR_EASR_IO', 'short write');
    written += count;
  }
};

const readExact = (fd, buffer, size, position) => {
  if (size > buffer.length) {
    fail('ERR_EASR_IO', 'payload chunk exceeds scratch buffer');
  }
  let read = 0;
  while (read < size) {
    const count = fs.readSync(fd, buffer, read, size - read, position + read);
    if (count <= 0) fail('ERR_EASR_IO', 'short read from payload spool');
    read += count;
  }
  return buffer.subarray(0, size);
};

const readStableFile = (item, buffer, onChunk) => {
  let fd;
  try {
    fd = fs.openSync(item.absolute, READ_NOFOLLOW);
  } catch (error) {
    fail('ERR_EASR_SOURCE_CHANGED',
      'source file could not be opened without following a link: ' +
      item.path, error);
  }
  const hash = crypto.createHash('sha256');
  let total = 0;
  try {
    const before = statSnapshot(fs.fstatSync(fd, { bigint: true }));
    if (!sameSnapshot(before, item.snapshot)) {
      fail('ERR_EASR_SOURCE_CHANGED',
        'source file changed before read: ' + item.path);
    }
    while (true) {
      const count = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (count === 0) break;
      const chunk = buffer.subarray(0, count);
      hash.update(chunk);
      if (onChunk) onChunk(chunk, total);
      total += count;
    }
    const after = statSnapshot(fs.fstatSync(fd, { bigint: true }));
    if (!sameSnapshot(after, item.snapshot) || total !== item.size) {
      fail('ERR_EASR_SOURCE_CHANGED',
        'source file changed during read: ' + item.path);
    }
    return hash.digest();
  } finally {
    safeClose(fd);
  }
};

const chooseStoredChunk = (plaintext, compressionEnabled, level) => {
  if (!compressionEnabled || plaintext.length === 0) {
    return { codec: 'raw', bytes: plaintext };
  }
  const compressed = zlib.deflateRawSync(plaintext, { level });
  const rawCost = plaintext.length + 1;
  const compressedCost = compressed.length +
    format.encodeUVarint(compressed.length).length;
  return compressedCost < rawCost
    ? { codec: 'deflate-raw', bytes: compressed }
    : { codec: 'raw', bytes: plaintext };
};

const estimateEntropy = bytes => {
  if (bytes.length === 0) return 0;
  const frequencies = new Uint32Array(256);
  for (const byte of bytes) frequencies[byte]++;
  let entropy = 0;
  for (const count of frequencies) {
    if (count === 0) continue;
    const probability = count / bytes.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
};

const initialCompressionState = (relativePath, size, enabled) => {
  if (!enabled) {
    return { mode: 'skip', hint: 'disabled' };
  }
  const extension = path.posix.extname(relativePath).toLowerCase();
  const hint = INCOMPRESSIBLE_EXTENSIONS.has(extension)
    ? 'incompressible'
    : (COMPRESSIBLE_EXTENSIONS.has(extension) ? 'compressible' : 'unknown');
  return {
    // Text-like inputs are tried block by block so a high-entropy prefix
    // cannot suppress compression of later source. Small assets are also
    // cheap to try; only large unknown/already-compressed inputs probe once.
    mode: hint === 'compressible' ||
      size <= SMALL_FILE_DIRECT_COMPRESSION_MAX
      ? 'compress'
      : 'probe',
    hint
  };
};

const chooseAdaptiveChunk = (plaintext, state, level) => {
  if (state.mode === 'skip') {
    return { codec: 'raw', bytes: plaintext, attempted: false };
  }
  const entropy = state.mode === 'probe' && state.hint === 'incompressible'
    ? estimateEntropy(plaintext)
    : null;
  const stored = chooseStoredChunk(plaintext, true, level);
  if (state.mode === 'probe') {
    state.mode = stored.codec === 'raw' ||
      (entropy !== null && entropy >= ENTROPY_SKIP_THRESHOLD)
      ? 'skip'
      : 'compress';
  }
  return { ...stored, attempted: plaintext.length !== 0 };
};

const normalizeOptions = options => {
  if (!options || typeof options !== 'object') {
    fail('ERR_EASR_PACK_FIELD', 'packer options are required');
  }
  let sourceRoot;
  try {
    sourceRoot = fs.realpathSync(path.resolve(options.source));
  } catch (error) {
    fail('ERR_EASR_SOURCE', 'source directory does not exist', error);
  }
  if (!fs.statSync(sourceRoot).isDirectory()) {
    fail('ERR_EASR_SOURCE', 'source must be a directory');
  }

  const requestedOutput = path.resolve(options.output);
  let outputParent;
  try {
    outputParent = fs.realpathSync(path.dirname(requestedOutput));
  } catch (error) {
    fail('ERR_EASR_OUTPUT_PARENT',
      'output parent directory does not exist', error);
  }
  const output = path.join(outputParent, path.basename(requestedOutput));
  if (isWithin(sourceRoot, output)) {
    fail('ERR_EASR_OUTPUT_IN_SOURCE',
      'encrypted archive output must be outside the source tree');
  }
  if (fs.existsSync(output) || fs.existsSync(output + '.unpacked')) {
    fail('ERR_EASR_OUTPUT_EXISTS',
      'output or authenticated unpack directory already exists');
  }

  const dataKey = Buffer.from(requireBuffer(
    options.dataKey,
    32,
    'data key',
    'ERR_EASR_DATA_KEY'
  ));
  try {
    if (!dataKey.some(byte => byte !== 0)) {
      dataKey.fill(0);
      fail('ERR_EASR_DATA_KEY', 'data key must not be all zero');
    }
    const signingPrivateKey = asSigningPrivateKey(options.signingPrivateKey);
    const derivedDataKeyId = format.deriveDataKeyId(dataKey);
    const derivedSigningKeyId = format.deriveSigningKeyId(signingPrivateKey);
    if (options.dataKeyId !== undefined) {
      const supplied = requireNonZeroBuffer(
        options.dataKeyId,
        16,
        'data key id'
      );
      if (!crypto.timingSafeEqual(supplied, derivedDataKeyId)) {
        dataKey.fill(0);
        fail('ERR_EASR_KEY_ID',
          'data key id does not match the supplied data key');
      }
    }
    if (options.signingKeyId !== undefined) {
      const supplied = requireNonZeroBuffer(
        options.signingKeyId,
        16,
        'signing key id'
      );
      if (!crypto.timingSafeEqual(supplied, derivedSigningKeyId)) {
        dataKey.fill(0);
        fail('ERR_EASR_KEY_ID',
          'signing key id does not match the signing public key');
      }
    }
    let epoch;
    try {
      epoch = typeof options.epoch === 'bigint'
        ? options.epoch
        : BigInt(options.epoch);
    } catch (error) {
      fail('ERR_EASR_EPOCH', 'epoch must be an unsigned integer', error);
    }
    if (epoch < BigInt(0) ||
      epoch > format.constants.UINT64_MAX) {
      fail('ERR_EASR_EPOCH', 'epoch is outside u64 range');
    }

    const blockSizeLog2 = options.blockSizeLog2 === undefined
      ? DEFAULT_BLOCK_SIZE_LOG2
      : options.blockSizeLog2;
    if (!Number.isInteger(blockSizeLog2) ||
      blockSizeLog2 < 12 || blockSizeLog2 > 20) {
      fail('ERR_EASR_BLOCK_SIZE', 'block size log2 must be between 12 and 20');
    }
    const compressionLevel = options.compressionLevel === undefined
      ? DEFAULT_COMPRESSION_LEVEL
      : options.compressionLevel;
    if (!Number.isInteger(compressionLevel) ||
      compressionLevel < 1 || compressionLevel > 9) {
      fail('ERR_EASR_COMPRESSION', 'compression level must be between 1 and 9');
    }
    if (options.unpack !== undefined &&
      (!options.unpack || typeof options.unpack[Symbol.iterator] !== 'function' ||
        typeof options.unpack === 'string')) {
      dataKey.fill(0);
      fail('ERR_EASR_UNPACK_PATH', 'unpack paths must be an iterable of paths');
    }
    const unpack = options.unpack === undefined ? new Set() : new Set(options.unpack);
    if (unpack.size > format.constants.MAX_ENTRY_COUNT) {
      dataKey.fill(0);
      fail('ERR_EASR_UNPACK_LIST_LIMIT', 'too many unpack paths');
    }
    const forbiddenSourceIdentities = new Set(
      options.forbiddenSourceIdentities || []
    );
    for (const identity of forbiddenSourceIdentities) {
      if (typeof identity !== 'string' || !/^\d+:\d+$/u.test(identity)) {
        dataKey.fill(0);
        fail('ERR_EASR_PACK_FIELD', 'invalid forbidden source identity');
      }
    }

    return {
      sourceRoot,
      output,
      outputParent,
      dataKey,
      dataKeyId: derivedDataKeyId,
      signingKeyId: derivedSigningKeyId,
      signingPrivateKey,
      epoch,
      blockSizeLog2,
      blockSize: 2 ** blockSizeLog2,
      compressionEnabled: options.compression !== false,
      compressionLevel,
      unpack,
      forbiddenSourceIdentities,
      trustWindowsOutputAcl: options.trustWindowsOutputAcl === true,
      hooks: options.hooks || {}
    };
  } catch (error) {
    dataKey.fill(0);
    throw error;
  }
};

const buildSpool = (normalized, inventory, workDirectory) => {
  const spoolPath = path.join(workDirectory, 'payload.spool');
  const spoolFd = fs.openSync(spoolPath, 'wx+', 0o600);
  const unpackRoot = path.join(workDirectory, 'unpacked');
  const sourceScratch = Buffer.allocUnsafe(normalized.blockSize);
  const entries = [];
  const unmatchedUnpack = new Set(normalized.unpack);
  const stats = {
    files: 0,
    directories: 0,
    symlinks: 0,
    unpackedFiles: 0,
    chunks: 0,
    compressedChunks: 0,
    compressionAttempts: 0,
    compressionSkippedBytes: 0,
    sourceBytes: 0,
    packedPlainBytes: 0,
    spoolBytes: 0
  };

  try {
    for (const item of inventory) {
      if (item.type === 'directory') {
        stats.directories++;
        entries.push({ path: item.path, type: 'directory' });
        continue;
      }
      if (item.type === 'symlink') {
        stats.symlinks++;
        entries.push({
          path: item.path,
          type: 'symlink',
          target: item.target
        });
        continue;
      }

      stats.files++;
      stats.sourceBytes += item.size;
      const unpacked = normalized.unpack.has(item.path);
      if (unpacked) unmatchedUnpack.delete(item.path);
      const executable = (item.mode & 0o111) !== 0;
      if (unpacked) {
        stats.unpackedFiles++;
        const stagedPath = path.join(
          unpackRoot,
          ...item.path.split('/')
        );
        fs.mkdirSync(path.dirname(stagedPath), {
          recursive: true,
          mode: 0o700
        });
        const stagedFd = fs.openSync(stagedPath, 'wx', 0o600);
        try {
          item.sourceDigest = readStableFile(
            item,
            sourceScratch,
            chunk => writeAll(stagedFd, chunk)
          );
          fs.fsyncSync(stagedFd);
        } finally {
          safeClose(stagedFd);
        }
        entries.push({
          path: item.path,
          type: 'file',
          unpacked: true,
          executable,
          size: item.size,
          digest: item.sourceDigest
        });
        continue;
      }

      const chunks = [];
      const compressionState = initialCompressionState(
        item.path,
        item.size,
        normalized.compressionEnabled
      );
      item.sourceDigest = readStableFile(
        item,
        sourceScratch,
        plaintext => {
          if (stats.chunks >= format.constants.MAX_ENCODER_CHUNK_COUNT) {
            fail('ERR_EASR_CHUNK_LIMIT',
              'encoder chunk limit exceeded; use a larger block size');
          }
          const stored = chooseAdaptiveChunk(
            plaintext,
            compressionState,
            normalized.compressionLevel
          );
          if (stored.attempted) {
            stats.compressionAttempts++;
          } else {
            stats.compressionSkippedBytes += plaintext.length;
          }
          writeAll(spoolFd, stored.bytes);
          chunks.push({
            codec: stored.codec,
            storedSize: stored.bytes.length,
            digest: crypto.createHash('sha256')
              .update(stored.bytes)
              .digest()
          });
          stats.chunks++;
          stats.packedPlainBytes += plaintext.length;
          stats.spoolBytes += stored.bytes.length;
          if (stored.codec === 'deflate-raw') stats.compressedChunks++;
        }
      );
      entries.push({
        path: item.path,
        type: 'file',
        executable,
        size: item.size,
        chunks
      });
    }
    if (unmatchedUnpack.size > 0) {
      fail('ERR_EASR_UNPACK_PATH',
        'unpack path is not a regular source file: ' +
        Array.from(unmatchedUnpack)[0]);
    }
    fs.fsyncSync(spoolFd);
    return { entries, spoolFd, spoolPath, unpackRoot, stats };
  } catch (error) {
    safeClose(spoolFd);
    throw error;
  } finally {
    sourceScratch.fill(0);
  }
};

const encryptSpool = (normalized, plan, spoolFd, archivePath,
  verifyPayload) => {
  const archiveFd = fs.openSync(archivePath, 'wx+', 0o600);
  const payloadOffset = format.constants.SUPERBLOCK_SIZE +
    plan.finalIndexSize;
  const tags = Buffer.allocUnsafe(
    plan.chunkCount * format.constants.TAG_SIZE
  );
  const payloadHash = verifyPayload ? crypto.createHash('sha256') : null;
  const payloadScratch = Buffer.allocUnsafe(normalized.blockSize);
  let hashedPayloadBytes = 0;
  let dataKey;
  try {
    dataKey = format.deriveDataKey(normalized.dataKey, plan);
    for (const chunk of plan.chunks) {
      const stored = readExact(
        spoolFd,
        payloadScratch,
        chunk.storedSize,
        chunk.payloadOffset
      );
      try {
        const digest = crypto.createHash('sha256').update(stored).digest();
        if (!crypto.timingSafeEqual(digest, chunk.digest)) {
          fail('ERR_EASR_SPOOL_CHANGED',
            'staged packed bytes changed before encryption');
        }
        const cipher = crypto.createCipheriv(
          'aes-256-gcm',
          dataKey,
          format.deriveChunkNonce(chunk.ordinal)
        );
        cipher.setAAD(format.buildChunkAad(plan, chunk));
        const ciphertext = cipher.update(stored);
        const finalCiphertext = cipher.final();
        if (ciphertext.length + finalCiphertext.length !== stored.length) {
          fail('ERR_EASR_CRYPTO', 'AES-GCM changed payload length');
        }
        if (chunk.payloadOffset !== hashedPayloadBytes) {
          fail('ERR_EASR_PAYLOAD_SIZE',
            'payload chunks are not in canonical physical order');
        }
        if (payloadHash) {
          payloadHash.update(ciphertext);
          payloadHash.update(finalCiphertext);
        }
        hashedPayloadBytes += ciphertext.length + finalCiphertext.length;
        writeAll(
          archiveFd,
          ciphertext,
          payloadOffset + chunk.payloadOffset
        );
        if (finalCiphertext.length > 0) {
          writeAll(
            archiveFd,
            finalCiphertext,
            payloadOffset + chunk.payloadOffset + ciphertext.length
          );
        }
        cipher.getAuthTag().copy(
          tags,
          chunk.ordinal * format.constants.TAG_SIZE
        );
      } finally {
        stored.fill(0);
      }
    }

    const finalized = format.finalizeArchive(plan, {
      tags,
      signingKeyId: normalized.signingKeyId,
      privateKey: normalized.signingPrivateKey
    });
    if (finalized.payloadOffset !== payloadOffset) {
      fail('ERR_EASR_INDEX_SIZE', 'final index size changed after encryption');
    }
    writeAll(archiveFd, finalized.superblock, 0);
    writeAll(
      archiveFd,
      finalized.index,
      format.constants.SUPERBLOCK_SIZE
    );
    if (hashedPayloadBytes !== finalized.payloadSize) {
      fail('ERR_EASR_PAYLOAD_SIZE', 'encrypted payload size changed');
    }
    fs.ftruncateSync(archiveFd, finalized.archiveSize);
    fs.fchmodSync(archiveFd, publishedMode(false));
    fs.fsyncSync(archiveFd);
    return Object.freeze({
      finalized,
      payloadDigest: payloadHash ? payloadHash.digest() : null,
      archiveSnapshot: Object.freeze(statSnapshot(
        fs.fstatSync(archiveFd, { bigint: true })
      ))
    });
  } finally {
    if (dataKey) dataKey.fill(0);
    payloadScratch.fill(0);
    safeClose(archiveFd);
  }
};

const revalidateSource = (normalized, inventory) => {
  let current;
  try {
    current = scanSource(normalized.sourceRoot);
  } catch (error) {
    if (error instanceof EasrPackerError &&
        error.code === 'ERR_EASR_SOURCE_CHANGED') {
      throw error;
    }
    fail('ERR_EASR_SOURCE_CHANGED',
      'source traversal changed during final revalidation', error);
  }
  assertInventoryMatches(inventory, current);
  const sourceScratch = Buffer.allocUnsafe(normalized.blockSize);
  try {
    for (const item of inventory) {
      if (item.type !== 'file') continue;
      const digest = readStableFile(item, sourceScratch);
      if (!crypto.timingSafeEqual(digest, item.sourceDigest)) {
        fail('ERR_EASR_SOURCE_CHANGED',
          'source contents changed during packing: ' + item.path);
      }
    }
  } finally {
    sourceScratch.fill(0);
  }
};

const hashOpenedFile = (fd, blockSize) => {
  const hash = crypto.createHash('sha256');
  const buffer = Buffer.allocUnsafe(blockSize);
  let total = 0;
  try {
    while (true) {
      const count = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (count === 0) break;
      hash.update(buffer.subarray(0, count));
      total += count;
    }
    return { digest: hash.digest(), total };
  } finally {
    buffer.fill(0);
  }
};

const verifyTemporaryArchive = (filename, encrypted, blockSize) => {
  let fd;
  const buffer = Buffer.allocUnsafe(blockSize);
  try {
    const pathStat = fs.lstatSync(filename, { bigint: true });
    if (!pathStat.isFile() || pathStat.isSymbolicLink()) {
      fail('ERR_EASR_ARCHIVE_CHANGED',
        'temporary archive is no longer a regular file');
    }
    fd = fs.openSync(filename, READ_NOFOLLOW);
    const before = statSnapshot(fs.fstatSync(fd, { bigint: true }));
    if (!sameSnapshot(statSnapshot(pathStat), before) ||
        !sameIdentity(before, encrypted.archiveSnapshot) ||
        before.size !== String(encrypted.finalized.archiveSize)) {
      fail('ERR_EASR_ARCHIVE_CHANGED',
        'temporary archive identity or size changed before publication');
    }

    const compareExpected = (expected, start) => {
      for (let offset = 0; offset < expected.length; offset += buffer.length) {
        const size = Math.min(buffer.length, expected.length - offset);
        const count = fs.readSync(fd, buffer, 0, size, start + offset);
        if (count !== size ||
            !buffer.subarray(0, size).equals(
              expected.subarray(offset, offset + size))) {
          fail('ERR_EASR_ARCHIVE_CHANGED',
            'temporary archive header or index changed before publication');
        }
      }
    };
    compareExpected(encrypted.finalized.superblock, 0);
    compareExpected(
      encrypted.finalized.index,
      format.constants.SUPERBLOCK_SIZE
    );

    const payloadHash = crypto.createHash('sha256');
    let total = 0;
    while (total < encrypted.finalized.payloadSize) {
      const size = Math.min(
        buffer.length,
        encrypted.finalized.payloadSize - total
      );
      const count = fs.readSync(
        fd,
        buffer,
        0,
        size,
        encrypted.finalized.payloadOffset + total
      );
      if (count !== size) {
        fail('ERR_EASR_ARCHIVE_CHANGED',
          'temporary archive payload was truncated before publication');
      }
      payloadHash.update(buffer.subarray(0, count));
      total += count;
    }
    const after = statSnapshot(fs.fstatSync(fd, { bigint: true }));
    if (!sameSnapshot(before, after) ||
        !crypto.timingSafeEqual(
          payloadHash.digest(),
          encrypted.payloadDigest
        )) {
      fail('ERR_EASR_ARCHIVE_CHANGED',
        'temporary archive payload changed before publication');
    }
  } catch (error) {
    if (error instanceof EasrPackerError) throw error;
    fail('ERR_EASR_ARCHIVE_CHANGED',
      'temporary archive could not be verified before publication', error);
  } finally {
    buffer.fill(0);
    safeClose(fd);
  }
};

const verifyUnpackedRoot = (root, entries, blockSize, setMode) => {
  for (const entry of entries) {
    if (entry.type !== 'file' || !entry.unpacked) continue;
    const filename = path.join(root, ...entry.path.split('/'));
    let fd;
    try {
      const pathStat = fs.lstatSync(filename, { bigint: true });
      if (pathStat.isSymbolicLink()) {
        fail('ERR_EASR_UNPACKED_CHANGED',
          'staged unpacked path became a symbolic link: ' + entry.path);
      }
      // Windows rejects fsync on a read-only descriptor. The staging pass also
      // persists the final mode, so open it read-write only for that pass.
      fd = fs.openSync(filename, setMode
        ? fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0)
        : READ_NOFOLLOW);
      const beforeStat = fs.fstatSync(fd, { bigint: true });
      const before = statSnapshot(beforeStat);
      if (!sameSnapshot(statSnapshot(pathStat), before)) {
        fail('ERR_EASR_UNPACKED_CHANGED',
          'staged unpacked path identity changed: ' + entry.path);
      }
      if (!beforeStat.isFile() || Number(beforeStat.size) !== entry.size) {
        fail('ERR_EASR_UNPACKED_CHANGED',
          'staged unpacked file shape changed: ' + entry.path);
      }
      const verified = hashOpenedFile(fd, blockSize);
      const after = statSnapshot(fs.fstatSync(fd, { bigint: true }));
      if (verified.total !== entry.size || !sameSnapshot(before, after) ||
          !crypto.timingSafeEqual(verified.digest, entry.digest)) {
        fail('ERR_EASR_UNPACKED_CHANGED',
          'staged unpacked bytes changed: ' + entry.path);
      }
      if (setMode) {
        fs.fchmodSync(fd, publishedMode(entry.executable));
        fs.fsyncSync(fd);
      }
    } catch (error) {
      if (error instanceof EasrPackerError) throw error;
      fail('ERR_EASR_UNPACKED_CHANGED',
        'staged unpacked file could not be verified: ' + entry.path,
        error);
    } finally {
      safeClose(fd);
    }
  }
};

const publishUnpackedNoClobber = (stagedRoot, destination, entries,
  blockSize) => {
  try {
    fs.mkdirSync(destination, publishedMode(true));
  } catch (error) {
    if (error.code === 'EEXIST') {
      fail('ERR_EASR_OUTPUT_EXISTS',
        'authenticated unpack directory appeared during packing', error);
    }
    fail('ERR_EASR_PUBLISH',
      'failed to reserve authenticated unpack directory', error);
  }

  const createdDirectories = new Set(['']);
  try {
    for (const entry of entries) {
      if (entry.type !== 'file' || !entry.unpacked) continue;
      const segments = entry.path.split('/');
      let relativeDirectory = '';
      for (const segment of segments.slice(0, -1)) {
        relativeDirectory = relativeDirectory
          ? relativeDirectory + '/' + segment
          : segment;
        if (createdDirectories.has(relativeDirectory)) continue;
        fs.mkdirSync(
          path.join(destination, ...relativeDirectory.split('/')),
          publishedMode(true)
        );
        createdDirectories.add(relativeDirectory);
      }
      const staged = path.join(stagedRoot, ...segments);
      const published = path.join(destination, ...segments);
      try {
        fs.linkSync(staged, published);
      } catch (error) {
        if (error.code === 'EEXIST') {
          fail('ERR_EASR_OUTPUT_EXISTS',
            'unpacked output path appeared during publication', error);
        }
        capabilityFailure('ERR_EASR_CAPABILITY_HARDLINK',
          'atomic unpacked-file publication requires same-volume hard links',
          'same-volume-hard-link-create-if-absent',
          error);
      }
    }
    verifyUnpackedRoot(destination, entries, blockSize, false);
    for (const relative of Array.from(createdDirectories).reverse()) {
      safeSyncDirectory(relative
        ? path.join(destination, ...relative.split('/'))
        : destination);
    }
    return true;
  } catch (error) {
    // `destination` is a public, predictable path. Pure Node has no
    // handle-relative recursive remove, so a writer in the output parent could
    // replace it between an identity check and rollback and turn the packer
    // into a privileged recursive-delete deputy. Leave it as an explicit
    // residual instead; private randomized work directories are still cleaned.
    error.easarRollbackPaths = [path.resolve(destination)];
    throw error;
  }
};

const publishArchiveNoClobber = (temporaryArchive, output) => {
  try {
    // A same-volume hard link is one atomic create-if-absent operation. It
    // closes the exists->rename clobber window without exposing partial bytes.
    fs.linkSync(temporaryArchive, output);
    safeSyncDirectory(path.dirname(output));
  } catch (error) {
    if (error.code === 'EEXIST' || fs.existsSync(output)) {
      fail('ERR_EASR_OUTPUT_EXISTS',
        'archive output appeared during packing', error);
    }
    capabilityFailure('ERR_EASR_CAPABILITY_HARDLINK',
      'atomic archive publication requires same-volume hard links',
      'same-volume-hard-link-create-if-absent', error);
  }
};

const cleanupErrorView = (error, target) => Object.freeze({
  path: path.resolve(target),
  code: error && error.code ? error.code : null,
  message: error && error.message ? error.message : String(error)
});

const securelyWipeFile = (filename, errors) => {
  let fd;
  try {
    const pathStat = fs.lstatSync(filename, { bigint: true });
    if (pathStat.isSymbolicLink()) {
      fs.unlinkSync(filename);
      return;
    }
    if (!pathStat.isFile()) return;
    fd = fs.openSync(
      filename,
      fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0)
    );
    const openedStat = fs.fstatSync(fd, { bigint: true });
    if (!sameSnapshot(statSnapshot(pathStat), statSnapshot(openedStat))) {
      throw new Error('cleanup file identity changed while opening');
    }
    const zeros = Buffer.alloc(64 * 1024);
    const size = Number(openedStat.size);
    for (let offset = 0; offset < size; offset += zeros.length) {
      writeAll(fd, zeros.subarray(0, Math.min(zeros.length, size - offset)),
        offset);
    }
    fs.fsyncSync(fd);
    fs.ftruncateSync(fd, 0);
    fs.fsyncSync(fd);
  } catch (error) {
    if (error.code !== 'ENOENT') {
      errors.push(cleanupErrorView(error, filename));
    }
  } finally {
    safeClose(fd);
  }
};

const wipeStagedTree = (directory, archiveCommitted, errors) => {
  let names;
  try {
    names = fs.readdirSync(directory);
  } catch (error) {
    if (error.code !== 'ENOENT') {
      errors.push(cleanupErrorView(error, directory));
    }
    return;
  }
  for (const name of names) {
    const filename = path.join(directory, name);
    let stat;
    try {
      stat = fs.lstatSync(filename);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        errors.push(cleanupErrorView(error, filename));
      }
      continue;
    }
    if (stat.isDirectory()) {
      wipeStagedTree(filename, archiveCommitted, errors);
      continue;
    }
    if (archiveCommitted) {
      // Published sidecar files are hard links. Remove only the private
      // staging name; overwriting it would corrupt the committed sidecar.
      try {
        fs.unlinkSync(filename);
      } catch (error) {
        if (error.code !== 'ENOENT') {
          errors.push(cleanupErrorView(error, filename));
        }
      }
    } else {
      securelyWipeFile(filename, errors);
    }
  }
};

const cleanupArtifacts = ({
  workDirectory,
  workDirectoryIdentity,
  privateCleanupAllowed,
  privateCleanupFailure,
  rollbackSidecar,
  sidecarPath,
  rollbackPaths,
  archiveCommitted
}) => {
  const failures = [];
  const wipeErrors = [];
  const residualPaths = [];
  let cleanupFailed = false;

  const preservePrivatePath = (target, error) => {
    const absolute = path.resolve(target);
    cleanupFailed = true;
    if (!residualPaths.includes(absolute)) residualPaths.push(absolute);
    failures.push(cleanupErrorView(error, absolute));
  };

  const removeWithWipeRetry = (target, expectedIdentity, wipe) => {
    if (!target) return;
    const absolute = path.resolve(target);
    if (!privateCleanupAllowed) {
      preservePrivatePath(absolute, privateCleanupFailure || Object.assign(
        new Error('output boundary changed before private cleanup'),
        { code: 'ERR_EASR_OUTPUT_BOUNDARY_CHANGED' }
      ));
      return;
    }
    try {
      const stat = fs.lstatSync(absolute, { bigint: true });
      if (!stat.isDirectory() || stat.isSymbolicLink() ||
          !expectedIdentity ||
          !sameIdentity(statSnapshot(stat), expectedIdentity)) {
        const error = new Error(
          'private work directory identity changed before cleanup');
        error.code = 'ERR_EASR_PRIVATE_CLEANUP_IDENTITY';
        preservePrivatePath(absolute, error);
        return;
      }
    } catch (error) {
      if (error.code === 'ENOENT') return;
      preservePrivatePath(absolute, error);
      return;
    }
    const firstError = safeRemove(absolute, { recursive: true });
    if (!firstError) return;
    cleanupFailed = true;
    failures.push(cleanupErrorView(firstError, absolute));
    wipe();
    const retryError = safeRemove(absolute, { recursive: true });
    if (retryError) {
      failures.push(cleanupErrorView(retryError, absolute));
      residualPaths.push(absolute);
    }
  };

  const preservePublicRollbackPath = target => {
    if (!target) return;
    const absolute = path.resolve(target);
    if (residualPaths.includes(absolute)) return;
    cleanupFailed = true;
    residualPaths.push(absolute);
    const error = new Error(
      'public rollback path was preserved for identity-safe manual cleanup');
    error.code = 'ERR_EASR_PUBLIC_ROLLBACK_RESIDUAL';
    failures.push(cleanupErrorView(error, absolute));
  };

  if (rollbackSidecar) {
    preservePublicRollbackPath(sidecarPath);
  }
  for (const rollbackPath of rollbackPaths || []) {
    if (rollbackSidecar && path.resolve(rollbackPath) ===
        path.resolve(sidecarPath)) {
      continue;
    }
    preservePublicRollbackPath(rollbackPath);
  }
  if (workDirectory) {
    removeWithWipeRetry(workDirectory, workDirectoryIdentity, () => {
      securelyWipeFile(
        path.join(workDirectory, 'payload.spool'),
        wipeErrors
      );
      wipeStagedTree(
        path.join(workDirectory, 'unpacked'),
        archiveCommitted,
        wipeErrors
      );
    });
  }

  const status = residualPaths.length > 0
    ? 'residual'
    : (cleanupFailed ? 'recovered' : 'clean');
  return Object.freeze({
    status,
    archiveCommitted,
    residualPaths: Object.freeze(residualPaths),
    failures: Object.freeze(failures),
    wipeErrors: Object.freeze(wipeErrors)
  });
};

const attachCleanupState = (error, cleanup) => {
  try {
    Object.defineProperty(error, 'cleanup', {
      configurable: true,
      enumerable: true,
      value: cleanup
    });
    return error;
  } catch (attachmentError) {
    const wrapped = new EasrPackerError(
      error.code || 'ERR_EASR_PACK',
      error.message || String(error),
      error
    );
    wrapped.cleanup = cleanup;
    return wrapped;
  }
};

const requireCleanCliResult = result => {
  if (!result || !result.cleanup || result.cleanup.status !== 'residual') {
    return result;
  }
  const error = new EasrPackerError(
    'ERR_EASR_CLEANUP_RESIDUAL',
    'archive committed, but private cleanup residuals remain: ' +
      result.cleanup.residualPaths.join(', ')
  );
  error.archiveCommitted = result.cleanup.archiveCommitted;
  error.cleanup = result.cleanup;
  throw error;
};

const packArchive = options => {
  const started = process.hrtime.bigint();
  const normalized = normalizeOptions(options);
  const hasMutationHooks = MUTATION_HOOK_NAMES.some(
    name => typeof normalized.hooks[name] === 'function'
  );
  let workDirectory;
  let workDirectoryIdentity;
  let spool;
  let encrypted;
  let finalized;
  let outputBoundary;
  let sidecarPublished = false;
  let archiveCommitted = false;
  let result;
  let primaryError;
  try {
    outputBoundary = preflightCapabilities(normalized.outputParent, {
      trustWindowsOutputAcl: normalized.trustWindowsOutputAcl
    }).outputBoundary;
    const inventory = scanSource(normalized.sourceRoot);
    for (const item of inventory) {
      if (item.type === 'file' && normalized.forbiddenSourceIdentities.has(
        item.snapshot.dev + ':' + item.snapshot.ino
      )) {
        fail('ERR_EASR_KEY_IN_SOURCE',
          'source tree must not contain a data or signing key: ' + item.path);
      }
    }

    // Validate portable paths and the complete symlink graph before creating
    // temporary files. Regular files are validation-only unpacked entries.
    format.createArchivePlan({
      entries: validationEntries(inventory, normalized.unpack),
      dataKeyId: normalized.dataKeyId,
      epoch: normalized.epoch,
      blockSizeLog2: normalized.blockSizeLog2
    });

    workDirectory = fs.mkdtempSync(
      path.join(normalized.outputParent, TEMP_PREFIX)
    );
    workDirectoryIdentity = Object.freeze(statSnapshot(
      fs.lstatSync(workDirectory, { bigint: true })
    ));
    spool = buildSpool(normalized, inventory, workDirectory);
    const plan = format.createArchivePlan({
      entries: spool.entries,
      dataKeyId: normalized.dataKeyId,
      epoch: normalized.epoch,
      blockSizeLog2: normalized.blockSizeLog2
    });
    // The trusted plan now owns every packed-chunk descriptor and digest.
    // Drop the spool-side object graph before encryption; unpacked entries
    // retain only their single file digest for final publication checks.
    for (const entry of spool.entries) {
      if (entry.type === 'file' && !entry.unpacked) entry.chunks = [];
    }
    if (typeof normalized.hooks.beforeEncrypt === 'function') {
      normalized.hooks.beforeEncrypt({ spoolPath: spool.spoolPath });
    }
    const temporaryArchive = path.join(workDirectory, 'archive.tmp');
    encrypted = encryptSpool(
      normalized,
      plan,
      spool.spoolFd,
      temporaryArchive,
      hasMutationHooks
    );
    finalized = encrypted.finalized;
    safeClose(spool.spoolFd);
    spool.spoolFd = null;

    if (typeof normalized.hooks.beforeSourceRevalidate === 'function') {
      normalized.hooks.beforeSourceRevalidate({
        sourceRoot: normalized.sourceRoot
      });
    }
    revalidateSource(normalized, inventory);
    if (typeof normalized.hooks.beforeCommit === 'function') {
      normalized.hooks.beforeCommit({
        temporaryArchive,
        stagedUnpackRoot: spool.unpackRoot,
        output: normalized.output
      });
    }

    if (spool.stats.unpackedFiles > 0) {
      // Reopen every staged file with no-follow semantics, hash it on that
      // same fd, then apply safe modes.
      verifyUnpackedRoot(
        spool.unpackRoot,
        spool.entries,
        normalized.blockSize,
        true
      );
    }

    if (spool.stats.unpackedFiles > 0) {
      revalidateOutputBoundary(outputBoundary, {
        trustWindowsOutputAcl: normalized.trustWindowsOutputAcl
      });
      sidecarPublished = publishUnpackedNoClobber(
        spool.unpackRoot,
        normalized.output + '.unpacked',
        spool.entries,
        normalized.blockSize
      );
      if (typeof normalized.hooks.afterSidecarPublish === 'function') {
        normalized.hooks.afterSidecarPublish({
          sidecar: normalized.output + '.unpacked'
        });
        // The public hook is a deliberate mutation boundary. A normal build
        // has no hook and pays no second sidecar traversal.
        verifyUnpackedRoot(
          normalized.output + '.unpacked',
          spool.entries,
          normalized.blockSize,
          false
        );
      }
    }

    // Hooks are test/debug mutation boundaries. Verify the exact finalized
    // bytes only when one is installed, keeping production packing single-pass
    // over the encrypted archive.
    if (hasMutationHooks) {
      verifyTemporaryArchive(
        temporaryArchive,
        encrypted,
        normalized.blockSize
      );
    }
    revalidateOutputBoundary(outputBoundary, {
      trustWindowsOutputAcl: normalized.trustWindowsOutputAcl
    });

    // Publish the archive last. A crash before this point can leave only an
    // orphan `<archive>.unpacked`. It is reported for identity-safe manual
    // cleanup rather than recursively removed through its public path. Once
    // this atomic link succeeds, both artifacts are complete.
    publishArchiveNoClobber(temporaryArchive, normalized.output);
    archiveCommitted = true;
    safeUnlink(temporaryArchive);

    const packMs = Number(process.hrtime.bigint() - started) / 1e6;
    result = {
      ...spool.stats,
      archiveBytes: finalized.archiveSize,
      superblockBytes: format.constants.SUPERBLOCK_SIZE,
      indexBytes: finalized.index.length,
      tagBytes: finalized.tagBytes,
      payloadBytes: finalized.payloadSize,
      compressionSavedBytes:
        spool.stats.packedPlainBytes - finalized.payloadSize,
      estimatedJsChunkBufferCeilingBytes: normalized.blockSize * 3,
      memoryModel: 'estimated O(indexBytes + blockSize); not an RSS reading',
      rssMeasurement:
        'run script/easar-v2-benchmark.js --slow for sampled process RSS',
      temporaryDiskBytes:
        spool.stats.spoolBytes + finalized.archiveSize,
      recoveryPolicy:
        'report orphan .unpacked for identity-safe manual cleanup',
      packMs
    };
  } catch (error) {
    primaryError = error;
  }

  if (spool && spool.spoolFd !== null && spool.spoolFd !== undefined) {
    safeClose(spool.spoolFd);
  }
  let privateCleanupAllowed = true;
  let privateCleanupFailure;
  if (workDirectory) {
    try {
      revalidateOutputBoundary(outputBoundary, {
        trustWindowsOutputAcl: normalized.trustWindowsOutputAcl
      });
    } catch (error) {
      privateCleanupAllowed = false;
      privateCleanupFailure = error;
    }
  }
  let cleanup;
  try {
    cleanup = cleanupArtifacts({
      workDirectory,
      workDirectoryIdentity,
      privateCleanupAllowed,
      privateCleanupFailure,
      rollbackSidecar: !archiveCommitted && sidecarPublished,
      sidecarPath: normalized.output + '.unpacked',
      rollbackPaths: primaryError && primaryError.easarRollbackPaths,
      archiveCommitted
    });
  } catch (cleanupError) {
    const residualPaths = workDirectory
      ? Object.freeze([path.resolve(workDirectory)])
      : Object.freeze([]);
    cleanup = Object.freeze({
      status: residualPaths.length > 0 ? 'residual' : 'recovered',
      archiveCommitted,
      residualPaths,
      failures: Object.freeze([
        cleanupErrorView(cleanupError, workDirectory || normalized.output)
      ]),
      wipeErrors: Object.freeze([])
    });
  } finally {
    normalized.dataKey.fill(0);
  }

  if (primaryError) throw attachCleanupState(primaryError, cleanup);
  return Object.freeze({ ...result, cleanup });
};

const readKeySource = (source, stdinBuffer, maximum, description) => {
  if (source === '-') {
    if (!Buffer.isBuffer(stdinBuffer)) {
      fail('ERR_EASR_KEY_FILE', 'controlled stdin key bytes are unavailable');
    }
    if (stdinBuffer.length > maximum) {
      fail('ERR_EASR_KEY_FILE_LIMIT',
        description + ' exceeds ' + maximum + ' bytes');
    }
    return Buffer.from(stdinBuffer);
  }
  let fd;
  try {
    const pathStat = fs.lstatSync(source, { bigint: true });
    if (pathStat.isSymbolicLink()) {
      fail('ERR_EASR_KEY_FILE', 'key path must not be a symbolic link');
    }
    fd = fs.openSync(source, READ_NOFOLLOW);
    const beforeStat = fs.fstatSync(fd, { bigint: true });
    const before = statSnapshot(beforeStat);
    if (!sameSnapshot(statSnapshot(pathStat), before)) {
      fail('ERR_EASR_KEY_FILE',
        'key path identity changed while it was opened');
    }
    if (!beforeStat.isFile()) {
      fail('ERR_EASR_KEY_FILE', 'key path must name a regular file');
    }
    if (beforeStat.size > BigInt(maximum)) {
      fail('ERR_EASR_KEY_FILE_LIMIT',
        description + ' exceeds ' + maximum + ' bytes');
    }
    if (process.platform === 'win32') {
      capabilityFailure(
        'ERR_EASR_KEY_ACL_UNVERIFIABLE',
        'pure Node cannot verify Windows key-file ACLs; provide keys through ' +
          'the programmatic API from a trusted secret provider',
        'windows-key-file-acl'
      );
    }
    if ((Number(beforeStat.mode) & 0o077) !== 0) {
      fail('ERR_EASR_KEY_PERMISSIONS',
        'key file must not be accessible by group or other users');
    }
    const result = readBoundedFd(
      fd,
      maximum,
      'ERR_EASR_KEY_FILE_LIMIT',
      description
    );
    const after = statSnapshot(fs.fstatSync(fd, { bigint: true }));
    if (!sameSnapshot(before, after) ||
        BigInt(result.length) !== beforeStat.size) {
      result.fill(0);
      fail('ERR_EASR_KEY_FILE', 'key file changed while it was read');
    }
    return result;
  } catch (error) {
    if (error instanceof EasrPackerError) throw error;
    fail('ERR_EASR_KEY_FILE', 'failed to read key file', error);
  } finally {
    safeClose(fd);
  }
};

const loadDataKey = (source, options = {}) => {
  const bytes = readKeySource(
    source,
    options.stdinBuffer,
    DATA_KEY_MAX_BYTES,
    'data key input'
  );
  try {
    let key;
    if (bytes.length === 32) {
      key = Buffer.from(bytes);
    } else {
      const text = bytes.toString('utf8').trim();
      if (!/^[0-9a-fA-F]{64}$/u.test(text)) {
        fail('ERR_EASR_DATA_KEY',
          'data key file must contain 32 raw bytes or 64 hex characters');
      }
      key = Buffer.from(text, 'hex');
    }
    if (!key.some(byte => byte !== 0)) {
      key.fill(0);
      fail('ERR_EASR_DATA_KEY', 'data key must not be all zero');
    }
    return key;
  } finally {
    bytes.fill(0);
  }
};

const loadSigningPrivateKey = (source, options = {}) => {
  const bytes = readKeySource(
    source,
    options.stdinBuffer,
    SIGNING_KEY_MAX_BYTES,
    'signing key input'
  );
  try {
    return asSigningPrivateKey(bytes);
  } finally {
    bytes.fill(0);
  }
};

const parseHexId = (value, name) => {
  if (typeof value !== 'string' || !/^[0-9a-fA-F]{32}$/u.test(value)) {
    fail('ERR_EASR_CLI_ARGUMENT', name + ' must be 32 hex characters');
  }
  const id = Buffer.from(value, 'hex');
  if (!id.some(byte => byte !== 0)) {
    fail('ERR_EASR_CLI_ARGUMENT', name + ' must not be all zero');
  }
  return id;
};

const parseCliArguments = argv => {
  const values = new Map();
  const booleans = new Set();
  const valueFlags = new Set([
    '--src',
    '--out',
    '--data-key-file',
    '--signing-key-file',
    '--data-key-id',
    '--signing-key-id',
    '--epoch',
    '--block-size-log2',
    '--compression-level',
    '--unpack-list'
  ]);
  const booleanFlags = new Set([
    '--no-compress',
    '--trust-windows-output-acl'
  ]);
  for (let index = 0; index < argv.length; index++) {
    const flag = argv[index];
    if (booleanFlags.has(flag)) {
      if (booleans.has(flag)) {
        fail('ERR_EASR_CLI_ARGUMENT', 'duplicate flag: ' + flag);
      }
      booleans.add(flag);
      continue;
    }
    if (!valueFlags.has(flag)) {
      fail('ERR_EASR_CLI_ARGUMENT', 'unknown argument: ' + flag);
    }
    if (values.has(flag) || index + 1 >= argv.length ||
        argv[index + 1].startsWith('--')) {
      fail('ERR_EASR_CLI_ARGUMENT', 'missing or duplicate value: ' + flag);
    }
    values.set(flag, argv[++index]);
  }
  if (!values.has('--data-key-file') ||
      !values.has('--signing-key-file')) {
    fail('ERR_EASR_KEY_REQUIRED',
      'data and signing private key files are required');
  }
  if (!values.has('--src') || !values.has('--out') ||
      !values.has('--epoch')) {
    fail('ERR_EASR_CLI_ARGUMENT', 'missing required non-secret argument');
  }
  if (values.get('--data-key-file') === '-' &&
      values.get('--signing-key-file') === '-') {
    fail('ERR_EASR_CLI_ARGUMENT',
      'only one key may be read from controlled stdin');
  }
  let epoch;
  try {
    if (!/^[0-9]+$/u.test(values.get('--epoch'))) throw new Error();
    epoch = BigInt(values.get('--epoch'));
  } catch (error) {
    fail('ERR_EASR_CLI_ARGUMENT', 'epoch must be an unsigned decimal integer');
  }
  return {
    source: values.get('--src'),
    output: values.get('--out'),
    dataKeyFile: values.get('--data-key-file'),
    signingKeyFile: values.get('--signing-key-file'),
    dataKeyId: values.has('--data-key-id')
      ? parseHexId(values.get('--data-key-id'), 'data key id')
      : undefined,
    signingKeyId: values.has('--signing-key-id')
      ? parseHexId(values.get('--signing-key-id'), 'signing key id')
      : undefined,
    epoch,
    blockSizeLog2: values.has('--block-size-log2')
      ? Number(values.get('--block-size-log2'))
      : DEFAULT_BLOCK_SIZE_LOG2,
    compressionLevel: values.has('--compression-level')
      ? Number(values.get('--compression-level'))
      : DEFAULT_COMPRESSION_LEVEL,
    compression: !booleans.has('--no-compress'),
    trustWindowsOutputAcl: booleans.has('--trust-windows-output-acl'),
    unpackList: values.get('--unpack-list') || null
  };
};

const readUnpackList = filename => {
  if (!filename) return new Set();
  let fd;
  let bytes;
  try {
    const pathStat = fs.lstatSync(filename, { bigint: true });
    if (pathStat.isSymbolicLink()) {
      fail('ERR_EASR_UNPACK_PATH',
        'unpack list must not be a symbolic link');
    }
    fd = fs.openSync(filename, READ_NOFOLLOW);
    const beforeStat = fs.fstatSync(fd, { bigint: true });
    const before = statSnapshot(beforeStat);
    if (!sameSnapshot(statSnapshot(pathStat), before)) {
      fail('ERR_EASR_UNPACK_PATH',
        'unpack list identity changed while it was opened');
    }
    if (!beforeStat.isFile()) {
      fail('ERR_EASR_UNPACK_PATH',
        'unpack list must be a regular file');
    }
    if (beforeStat.size > BigInt(UNPACK_LIST_MAX_BYTES)) {
      fail('ERR_EASR_UNPACK_LIST_LIMIT',
        'unpack list exceeds ' + UNPACK_LIST_MAX_BYTES + ' bytes');
    }
    bytes = readBoundedFd(
      fd,
      UNPACK_LIST_MAX_BYTES,
      'ERR_EASR_UNPACK_LIST_LIMIT',
      'unpack list'
    );
    const after = statSnapshot(fs.fstatSync(fd, { bigint: true }));
    if (!sameSnapshot(before, after) ||
        BigInt(bytes.length) !== beforeStat.size) {
      fail('ERR_EASR_UNPACK_PATH',
        'unpack list changed while it was read');
    }
  } catch (error) {
    if (error instanceof EasrPackerError) throw error;
    fail('ERR_EASR_UNPACK_PATH', 'failed to read unpack list', error);
  } finally {
    safeClose(fd);
  }
  try {
    const lines = bytes.toString('utf8')
      .split(/\r?\n/u)
      .filter(line => line.length > 0);
    if (lines.length > format.constants.MAX_ENTRY_COUNT) {
      fail('ERR_EASR_UNPACK_LIST_LIMIT', 'unpack list has too many paths');
    }
    return new Set(lines);
  } finally {
    bytes.fill(0);
  }
};

const runCli = (argv, options = {}) => {
  const parsed = parseCliArguments(argv);
  const stdinRequested = parsed.dataKeyFile === '-' ||
    parsed.signingKeyFile === '-';
  const stdinMaximum = parsed.dataKeyFile === '-'
    ? DATA_KEY_MAX_BYTES
    : SIGNING_KEY_MAX_BYTES;
  let stdinBuffer;
  let dataKey;
  try {
    const unpack = readUnpackList(parsed.unpackList);
    if (stdinRequested) {
      if (options.stdinBuffer !== undefined &&
          !Buffer.isBuffer(options.stdinBuffer)) {
        fail('ERR_EASR_KEY_FILE',
          'programmatic stdinBuffer must be a Buffer');
      }
      if (options.stdinBuffer !== undefined &&
          options.stdinBuffer.byteLength > stdinMaximum) {
        fail('ERR_EASR_KEY_FILE_LIMIT',
          'controlled stdin key input exceeds its limit');
      }
      stdinBuffer = options.stdinBuffer === undefined
        ? readBoundedFd(
          0,
          stdinMaximum,
          'ERR_EASR_KEY_FILE_LIMIT',
          'controlled stdin key input'
        )
        : Buffer.from(options.stdinBuffer);
    }
    const forbiddenSourceIdentities = [
      parsed.dataKeyFile,
      parsed.signingKeyFile
    ].filter(filename => filename !== '-').map(filename => {
      const stat = fs.statSync(filename, { bigint: true });
      return sourceIdentity(stat);
    });
    dataKey = loadDataKey(parsed.dataKeyFile, { stdinBuffer });
    return packArchive({
      source: parsed.source,
      output: parsed.output,
      dataKey,
      signingPrivateKey: loadSigningPrivateKey(
        parsed.signingKeyFile,
        { stdinBuffer }
      ),
      dataKeyId: parsed.dataKeyId,
      signingKeyId: parsed.signingKeyId,
      epoch: parsed.epoch,
      blockSizeLog2: parsed.blockSizeLog2,
      compressionLevel: parsed.compressionLevel,
      compression: parsed.compression,
      trustWindowsOutputAcl: parsed.trustWindowsOutputAcl,
      unpack,
      forbiddenSourceIdentities
    });
  } finally {
    if (dataKey) dataKey.fill(0);
    if (stdinBuffer) stdinBuffer.fill(0);
  }
};

module.exports = {
  EasrPackerError,
  getPlatformContract,
  loadDataKey,
  loadSigningPrivateKey,
  normalizeSymlinkTarget,
  packArchive,
  parseCliArguments,
  preflightCapabilities,
  requireCleanCliResult,
  runCli
};

/* global BigInt */

const crypto = require('crypto');
const { TextDecoder } = require('util');

// EASR v2 is deliberately small and eager only for metadata:
//
//   [200-byte signed superblock][canonical EIDX][ciphertext payload]
//
// The Ed25519 signature covers the fixed superblock prefix, which contains the
// SHA-256 digest of the complete index. The index therefore needs one
// signature regardless of archive size. Its final table is exactly one 16-byte
// AES-GCM tag per payload chunk; nonces are derived and never serialized.
//
// Files and chunks have no offsets on disk. Canonically sorted file entries and
// chunk stored lengths imply one contiguous, non-overlapping payload layout.
// Parsing the authenticated compact index once builds O(1) chunk offsets while
// payload ciphertext remains lazy.
//
// Superblock (all integers little-endian):
//   0  magic[4] = EASR          4  u32 version = 2
//   8  u16 size = 200          10  u8 signature algorithm = Ed25519
//  11  u8 data algorithm       12  u32 flags (high 16 bits are critical)
//  16  u32 index size          20  u32 reserved = 0
//  24  u64 payload size        32  u64 rollback epoch
//  40  data-key id[16]         56  signing-key id[16]
//  72  archive id[32]         104  SHA-256(index)[32]
// 136  Ed25519 signature[64] over domain || bytes[0, 136)
//
// Compact index:
//   EIDX | u8 version | u8 critical flags | u8 optional flags |
//   u8 block-size log2 | uvarint entry count | uvarint chunk count |
//   entries | 16-byte GCM tags in global chunk order
//
// Each entry starts with minimal uvarint(previous-path prefix bytes), minimal
// uvarint(suffix bytes), suffix, and one kind/flags byte. A packed file then
// has logical-size and one descriptor varint per implied logical block:
// descriptor 0 means raw (stored size is implicit); a positive descriptor is
// the smaller raw-DEFLATE stored size. No chunk nonce, offset, or hash is
// serialized.

const MAGIC = Buffer.from('EASR', 'ascii');
const FORMAT_VERSION = 2;
const SUPERBLOCK_SIZE = 200;
const SIGNATURE_OFFSET = 136;
const SIGNATURE_SIZE = 64;
const SUPERBLOCK_FLAGS_OFFSET = 12;
const SUPERBLOCK_INDEX_SIZE_OFFSET = 16;
const SUPERBLOCK_RESERVED_OFFSET = 20;
const SUPERBLOCK_PAYLOAD_SIZE_OFFSET = 24;
const SUPERBLOCK_EPOCH_OFFSET = 32;
const SUPERBLOCK_DATA_KEY_ID_OFFSET = 40;
const SUPERBLOCK_SIGNING_KEY_ID_OFFSET = 56;
const SUPERBLOCK_ARCHIVE_ID_OFFSET = 72;
const SUPERBLOCK_INDEX_HASH_OFFSET = 104;
const KEY_ID_SIZE = 16;
const ARCHIVE_ID_SIZE = 32;
const INDEX_HASH_SIZE = 32;
const SIGNATURE_ALGORITHM_ED25519 = 1;
const DATA_ALGORITHM_AES_256_GCM = 1;
const SIGNATURE_DOMAIN = Buffer.from(
  'EASR-v2-superblock-signature\u0000',
  'ascii'
);
const ARCHIVE_ID_DOMAIN = Buffer.from('EASR-v2-archive-id\u0000', 'ascii');
const DATA_KEY_ID_DOMAIN = Buffer.from('EASR-v2-data-key-id\u0000', 'ascii');
const SIGNING_KEY_ID_DOMAIN = Buffer.from(
  'EASR-v2-signing-key-id\u0000',
  'ascii'
);

const INDEX_MAGIC = Buffer.from('EIDX', 'ascii');
const INDEX_VERSION = 1;
const INDEX_CRITICAL_FLAGS_OFFSET = 5;
const INDEX_HEADER_SIZE = 8;
const MIN_BLOCK_SIZE_LOG2 = 12;
const MAX_BLOCK_SIZE_LOG2 = 20;
const DEFAULT_BLOCK_SIZE_LOG2 = 16;

const ENTRY_DIRECTORY = 0;
const ENTRY_FILE = 1;
const ENTRY_SYMLINK = 2;
const ENTRY_KIND_MASK = 3;
const ENTRY_EXECUTABLE = 4;
const ENTRY_UNPACKED = 8;
const ENTRY_KNOWN_FLAGS = ENTRY_KIND_MASK | ENTRY_EXECUTABLE | ENTRY_UNPACKED;

const CODEC_RAW = 0;
const CODEC_DEFLATE_RAW = 1;
const TAG_SIZE = 16;
const DIGEST_SIZE = 32;

// The whole authenticated index is eager by design. Keep its hard ceiling small
// enough for desktop startup and for the reference codec's object overhead.
const MAX_INDEX_SIZE = 16 * 1024 * 1024;
const MAX_ENTRY_COUNT = 262144;
const MAX_CHUNK_COUNT = 262144;
// Keep the pure-JS encoder's peak metadata bounded. At the default 64 KiB
// block size this still permits roughly 4 GiB of packed input, while the
// decoder retains the wider on-disk compatibility limit above.
const MAX_ENCODER_CHUNK_COUNT = 65536;
const MAX_PATH_BYTES = 4096;
// Prefix compression bounds the encoded index, not the decoded path strings.
// Keep the eager decoder's aggregate path storage aligned with the runtime.
const MAX_EXPANDED_PATH_BYTES = 64 * 1024 * 1024;
const MAX_PATH_SEGMENT_BYTES = 255;
const MAX_SYMLINK_DEPTH = 40;
const MAX_SAFE_INTEGER = BigInt(Number.MAX_SAFE_INTEGER);
const UINT32_MAX = BigInt(0xffffffff);
const UINT64_MAX = (BigInt(1) << BigInt(64)) - BigInt(1);

const AAD_DOMAIN = Buffer.alloc(16);
Buffer.from('EASR2-DATA-AAD', 'ascii').copy(AAD_DOMAIN);
const DATA_KEY_DOMAIN = Buffer.from('EASR-v2-data-key\u0000', 'ascii');
const NONCE_DOMAIN = Buffer.from('EA2D', 'ascii');

const utf8Decoder = new TextDecoder('utf-8', { fatal: true });
const archivePlanStates = new WeakMap();
const verifiedHeaderStates = new WeakMap();
const chunkContextStates = new WeakMap();

const WINDOWS_DEVICE_BASENAME = /^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])$/iu;
const WINDOWS_FORBIDDEN_PATH_CHARACTERS = '<>"|?*';

const ArchiveKind = Object.freeze({
  STANDARD_ASAR: 'standard-asar',
  EASR_V1: 'easr-v1',
  EASR_V2: 'easr-v2'
});

class EasrFormatError extends Error {
  constructor (code, message) {
    super(message);
    this.name = 'EasrFormatError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new EasrFormatError(code, message);
};

const requireBuffer = (value, size, name) => {
  if (!Buffer.isBuffer(value) || (size !== undefined && value.length !== size)) {
    fail('ERR_EASR_FIELD', name + ' has an invalid byte length');
  }
  return value;
};

const requireNonZeroBuffer = (value, size, name) => {
  requireBuffer(value, size, name);
  let nonZero = false;
  for (const byte of value) nonZero = nonZero || byte !== 0;
  if (!nonZero) fail('ERR_EASR_FIELD', name + ' must not be all zero');
  return value;
};

const toUnsignedBigInt = (value, maximum = UINT64_MAX, code = 'ERR_EASR_INTEGER') => {
  let integer;
  if (typeof value === 'bigint') {
    integer = value;
  } else if (typeof value === 'number' && Number.isSafeInteger(value)) {
    integer = BigInt(value);
  } else {
    fail(code, 'expected an unsigned integer');
  }
  if (integer < BigInt(0) || integer > maximum) {
    fail(code, 'unsigned integer is outside the allowed range');
  }
  return integer;
};

const toSafeNumber = (value, maximum, code) => {
  const integer = toUnsignedBigInt(value, BigInt(maximum), code);
  return Number(integer);
};

const encodeUVarint = (value) => {
  let integer = toUnsignedBigInt(value, UINT64_MAX, 'ERR_EASR_VARINT_OVERFLOW');
  const output = [];
  do {
    let byte = Number(integer & BigInt(0x7f));
    integer >>= BigInt(7);
    if (integer !== BigInt(0)) byte |= 0x80;
    output.push(byte);
  } while (integer !== BigInt(0));
  return Buffer.from(output);
};

const decodeUVarint = (buffer, offset = 0) => {
  requireBuffer(buffer, undefined, 'varint buffer');
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > buffer.length) {
    fail('ERR_EASR_INTEGER', 'invalid varint offset');
  }

  let value = BigInt(0);
  for (let index = 0; index < 10; index++) {
    if (offset + index >= buffer.length) {
      fail('ERR_EASR_TRUNCATED', 'truncated unsigned varint');
    }
    const byte = buffer[offset + index];
    if (index === 9 && byte > 1) {
      fail('ERR_EASR_VARINT_OVERFLOW', 'unsigned varint exceeds 64 bits');
    }
    value |= BigInt(byte & 0x7f) << BigInt(index * 7);
    if ((byte & 0x80) === 0) {
      if (index > 0 && (byte & 0x7f) === 0) {
        fail('ERR_EASR_NON_CANONICAL_VARINT',
          'unsigned varint is not minimally encoded');
      }
      return { value, offset: offset + index + 1 };
    }
  }
  fail('ERR_EASR_VARINT_OVERFLOW', 'unsigned varint exceeds 64 bits');
};

class IndexReader {
  constructor (buffer) {
    this.buffer = buffer;
    this.offset = 0;
  }

  readByte () {
    if (this.offset >= this.buffer.length) {
      fail('ERR_EASR_TRUNCATED', 'truncated index');
    }
    return this.buffer[this.offset++];
  }

  readBytes (length) {
    if (!Number.isSafeInteger(length) || length < 0 ||
        length > this.buffer.length - this.offset) {
      fail('ERR_EASR_TRUNCATED', 'truncated index field');
    }
    const value = this.buffer.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  readVarint (maximum, code) {
    const decoded = decodeUVarint(this.buffer, this.offset);
    this.offset = decoded.offset;
    if (decoded.value > BigInt(maximum)) {
      fail(code, 'index integer exceeds its strict limit');
    }
    return Number(decoded.value);
  }

  remaining () {
    return this.buffer.length - this.offset;
  }
}

const decodeUtf8 = (buffer) => {
  try {
    const value = utf8Decoder.decode(buffer);
    if (!Buffer.from(value, 'utf8').equals(buffer)) {
      fail('ERR_EASR_INVALID_UTF8', 'non-canonical UTF-8');
    }
    return value;
  } catch (error) {
    if (error instanceof EasrFormatError) throw error;
    fail('ERR_EASR_INVALID_UTF8', 'invalid UTF-8');
  }
};

const hasForbiddenWindowsPathCharacter = value => {
  for (let index = 0; index < value.length; index++) {
    const codeUnit = value.charCodeAt(index);
    if ((codeUnit >= 1 && codeUnit <= 0x1f) ||
        WINDOWS_FORBIDDEN_PATH_CHARACTERS.includes(value[index])) {
      return true;
    }
  }
  return false;
};

const validateCanonicalPath = (value) => {
  if (typeof value !== 'string' || value.length === 0 ||
      value !== value.normalize('NFC') ||
      value.startsWith('/') || value.endsWith('/') ||
      value.includes('\\') || value.includes('\u0000') ||
      value.includes(':') || hasForbiddenWindowsPathCharacter(value)) {
    fail('ERR_EASR_NON_CANONICAL_PATH', 'path is not canonical');
  }
  const encoded = Buffer.from(value, 'utf8');
  if (encoded.length === 0 || encoded.length > MAX_PATH_BYTES) {
    fail('ERR_EASR_NON_CANONICAL_PATH', 'path exceeds its byte limit');
  }
  if (decodeUtf8(encoded) !== value) {
    fail('ERR_EASR_INVALID_UTF8', 'path is not a lossless UTF-8 string');
  }
  for (const segment of value.split('/')) {
    const length = Buffer.byteLength(segment, 'utf8');
    if (segment.length === 0 || segment === '.' || segment === '..' ||
        length > MAX_PATH_SEGMENT_BYTES ||
        segment.endsWith('.') || segment.endsWith(' ') ||
        WINDOWS_DEVICE_BASENAME.test(segment.split('.')[0])) {
      fail('ERR_EASR_NON_CANONICAL_PATH', 'path contains an invalid segment');
    }
  }
  return encoded;
};

const portablePathKey = value => value.toUpperCase().normalize('NFC');

const rejectPortablePathCollisions = (entries) => {
  const paths = new Map();
  for (const entry of entries) {
    const key = portablePathKey(entry.path);
    const previous = paths.get(key);
    if (previous && previous !== entry.path) {
      fail('ERR_EASR_PATH_COLLISION',
        'paths collide on a case-insensitive filesystem');
    }
    paths.set(key, entry.path);
  }
};

const commonPrefixLength = (left, right) => {
  const length = Math.min(left.length, right.length);
  let index = 0;
  while (index < length && left[index] === right[index]) index++;
  return index;
};

const entryTypeFromFlags = (flags) => {
  if ((flags & ~ENTRY_KNOWN_FLAGS) !== 0) {
    fail('ERR_EASR_CRITICAL_FLAGS', 'unknown critical entry flags');
  }
  const kind = flags & ENTRY_KIND_MASK;
  if (kind === ENTRY_DIRECTORY) {
    if (flags !== ENTRY_DIRECTORY) {
      fail('ERR_EASR_ENTRY_FLAGS', 'directory has file-only flags');
    }
    return 'directory';
  }
  if (kind === ENTRY_SYMLINK) {
    if (flags !== ENTRY_SYMLINK) {
      fail('ERR_EASR_ENTRY_FLAGS', 'symlink has file-only flags');
    }
    return 'symlink';
  }
  if (kind !== ENTRY_FILE) {
    fail('ERR_EASR_ENTRY_FLAGS', 'reserved entry kind');
  }
  return 'file';
};

const entryFlags = (entry) => {
  if (entry.type === 'directory') {
    if (entry.executable || entry.unpacked) {
      fail('ERR_EASR_ENTRY_FLAGS', 'directory has file-only flags');
    }
    return ENTRY_DIRECTORY;
  }
  if (entry.type === 'symlink') {
    if (entry.executable || entry.unpacked) {
      fail('ERR_EASR_ENTRY_FLAGS', 'symlink has file-only flags');
    }
    return ENTRY_SYMLINK;
  }
  if (entry.type !== 'file') {
    fail('ERR_EASR_ENTRY_FLAGS', 'unknown entry kind');
  }
  return ENTRY_FILE |
    (entry.executable ? ENTRY_EXECUTABLE : 0) |
    (entry.unpacked ? ENTRY_UNPACKED : 0);
};

const parentPath = (path) => {
  const separator = path.lastIndexOf('/');
  return separator < 0 ? null : path.slice(0, separator);
};

const validateTree = (entries) => {
  rejectPortablePathCollisions(entries);
  const byPath = new Map();
  for (const entry of entries) {
    const parent = parentPath(entry.path);
    if (parent !== null) {
      const parentEntry = byPath.get(parent);
      if (!parentEntry) {
        fail('ERR_EASR_MISSING_PARENT', 'entry parent is missing');
      }
      if (parentEntry.type !== 'directory') {
        fail('ERR_EASR_PARENT_NOT_DIRECTORY',
          'entry parent is not a directory');
      }
    }
    byPath.set(entry.path, entry);
  }

  for (const entry of entries) {
    if (entry.type !== 'symlink') continue;
    if (!byPath.has(entry.target)) {
      fail('ERR_EASR_SYMLINK_TARGET', 'symlink target is missing');
    }
    const visited = new Set([entry.path]);
    let current = entry;
    let depth = 0;
    while (current.type === 'symlink') {
      if (++depth > MAX_SYMLINK_DEPTH) {
        fail('ERR_EASR_SYMLINK_DEPTH', 'symlink chain is too deep');
      }
      if (visited.has(current.target)) {
        fail('ERR_EASR_SYMLINK_CYCLE', 'symlink cycle');
      }
      visited.add(current.target);
      current = byPath.get(current.target);
      if (!current) {
        fail('ERR_EASR_SYMLINK_TARGET', 'symlink target is missing');
      }
    }
  }
};

const normalizeEntryForEncoding = (
  entry,
  blockSize,
  fileOrdinal,
  pathBytes
) => {
  if (!entry || typeof entry !== 'object') {
    fail('ERR_EASR_FIELD', 'entry must be an object');
  }
  const flags = entryFlags(entry);
  const normalized = {
    ...entry,
    pathBytes,
    flags,
    fileOrdinal
  };

  if (entry.type === 'symlink') {
    normalized.targetBytes = validateCanonicalPath(entry.target);
    return normalized;
  }
  if (entry.type !== 'file') return normalized;

  normalized.size = toSafeNumber(
    entry.size,
    Number.MAX_SAFE_INTEGER,
    'ERR_EASR_FILE_SIZE'
  );
  if (entry.unpacked) {
    requireBuffer(entry.digest, DIGEST_SIZE, 'unpacked digest');
    if (entry.chunks && entry.chunks.length !== 0) {
      fail('ERR_EASR_CHUNK_COUNT', 'unpacked file has payload chunks');
    }
    normalized.digest = Buffer.from(entry.digest);
    normalized.chunks = [];
    return normalized;
  }

  const expectedChunks = normalized.size === 0
    ? 0
    : Math.floor((normalized.size - 1) / blockSize) + 1;
  if (!Array.isArray(entry.chunks) ||
      entry.chunks.length !== expectedChunks) {
    fail('ERR_EASR_CHUNK_COUNT', 'file has inconsistent chunk geometry');
  }
  normalized.chunks = entry.chunks.map((chunk, chunkInFile) => {
    if (!chunk || typeof chunk !== 'object') {
      fail('ERR_EASR_FIELD', 'chunk must be an object');
    }
    const plainSize = Math.min(
      blockSize,
      normalized.size - chunkInFile * blockSize
    );
    const storedSize = toSafeNumber(
      chunk.storedSize,
      blockSize,
      'ERR_EASR_CHUNK_SIZE'
    );
    let codec;
    let descriptor;
    if (chunk.codec === 'raw') {
      if (storedSize !== plainSize) {
        fail('ERR_EASR_CHUNK_SIZE', 'raw chunk size must be implicit');
      }
      codec = CODEC_RAW;
      descriptor = 0;
    } else if (chunk.codec === 'deflate-raw') {
      if (storedSize === 0 || storedSize >= plainSize) {
        fail('ERR_EASR_CHUNK_SIZE',
          'compressed chunk must be smaller than plaintext');
      }
      codec = CODEC_DEFLATE_RAW;
      descriptor = storedSize;
    } else {
      fail('ERR_EASR_CODEC', 'unknown chunk codec');
    }
    requireBuffer(chunk.digest, DIGEST_SIZE, 'stored chunk digest');
    return {
      codec,
      descriptor,
      storedSize,
      plainSize,
      digest: chunk.digest,
      chunkInFile
    };
  });
  return normalized;
};

const makeChunkContext = (ownerState, chunk) => {
  const context = {};
  Object.defineProperties(context, {
    ordinal: { enumerable: true, value: chunk.ordinal },
    fileOrdinal: { enumerable: true, value: chunk.fileOrdinal },
    chunkInFile: { enumerable: true, value: chunk.chunkInFile },
    logicalOffset: { enumerable: true, value: chunk.logicalOffset },
    plainSize: { enumerable: true, value: chunk.plainSize },
    storedSize: { enumerable: true, value: chunk.storedSize },
    codec: { enumerable: true, value: chunk.codec },
    codecName: {
      enumerable: true,
      value: chunk.codec === CODEC_RAW ? 'raw' : 'deflate-raw'
    },
    entryFlags: { enumerable: true, value: chunk.entryFlags },
    payloadOffset: { enumerable: true, value: chunk.payloadOffset },
    digest: {
      enumerable: true,
      get: () => Buffer.from(
        ownerState.chunkDigests
          ? ownerState.chunkDigests.subarray(
            chunk.ordinal * DIGEST_SIZE,
            (chunk.ordinal + 1) * DIGEST_SIZE
          )
          : chunk.digest
      )
    },
    tag: {
      enumerable: chunk.tag !== undefined && chunk.tag !== null,
      get: () => chunk.tag ? Buffer.from(chunk.tag) : undefined
    }
  });
  Object.freeze(context);
  chunkContextStates.set(context, { ownerState, chunk });
  return context;
};

const makeArchivePlanView = (state) => {
  const plan = {};
  Object.defineProperties(plan, {
    archiveId: { enumerable: true, get: () => Buffer.from(state.archiveId) },
    dataKeyId: { enumerable: true, get: () => Buffer.from(state.dataKeyId) },
    epoch: { enumerable: true, get: () => state.epoch },
    payloadSize: { enumerable: true, get: () => state.payloadSize },
    indexCoreSize: { enumerable: true, get: () => state.indexCore.length },
    finalIndexSize: { enumerable: true, get: () => state.finalIndexSize },
    entryCount: { enumerable: true, get: () => state.entryCount },
    chunkCount: { enumerable: true, get: () => state.chunks.length },
    blockSize: { enumerable: true, get: () => state.blockSize },
    blockSizeLog2: { enumerable: true, get: () => state.blockSizeLog2 },
    chunks: { enumerable: true, get: () => state.chunkCollection }
  });
  Object.freeze(plan);
  archivePlanStates.set(plan, state);
  return plan;
};

const makeLazyChunkCollection = state => {
  const target = {};
  Object.defineProperties(target, {
    length: { enumerable: true, value: state.chunks.length },
    [Symbol.iterator]: {
      value: function * () {
        for (const chunk of state.chunks) {
          yield makeChunkContext(state, chunk);
        }
      }
    }
  });
  Object.freeze(target);
  return new Proxy(target, {
    get: (object, property, receiver) => {
      if (typeof property === 'string' && /^(?:0|[1-9][0-9]*)$/u.test(property)) {
        const index = Number(property);
        return index < state.chunks.length
          ? makeChunkContext(state, state.chunks[index])
          : undefined;
      }
      return Reflect.get(object, property, receiver);
    },
    set: () => false
  });
};

const createArchivePlan = (options) => {
  if (!options || !Array.isArray(options.entries)) {
    fail('ERR_EASR_FIELD', 'archive plan entries are required');
  }
  requireNonZeroBuffer(options.dataKeyId, KEY_ID_SIZE, 'data key id');
  const dataKeyId = Buffer.from(options.dataKeyId);
  const epoch = toUnsignedBigInt(options.epoch, UINT64_MAX, 'ERR_EASR_EPOCH');
  const blockSizeLog2 = options.blockSizeLog2 === undefined
    ? DEFAULT_BLOCK_SIZE_LOG2
    : options.blockSizeLog2;
  if (!Number.isInteger(blockSizeLog2) ||
      blockSizeLog2 < MIN_BLOCK_SIZE_LOG2 ||
      blockSizeLog2 > MAX_BLOCK_SIZE_LOG2) {
    fail('ERR_EASR_BLOCK_SIZE', 'block size exponent is outside its limit');
  }
  const optionalFlags = options.optionalFlags || 0;
  if (!Number.isInteger(optionalFlags) ||
      optionalFlags < 0 || optionalFlags > 0xff) {
    fail('ERR_EASR_FIELD', 'index optional flags are invalid');
  }
  if (options.criticalFlags) {
    fail('ERR_EASR_CRITICAL_FLAGS', 'unknown critical index flags');
  }
  if (options.entries.length > MAX_ENTRY_COUNT) {
    fail('ERR_EASR_ENTRY_LIMIT', 'too many index entries');
  }

  const blockSize = 2 ** blockSizeLog2;
  let expandedPathBytes = 0;
  const prepared = options.entries.map((entry, ordinal) => {
    const pathBytes = validateCanonicalPath(entry && entry.path);
    if (expandedPathBytes > MAX_EXPANDED_PATH_BYTES - pathBytes.length) {
      fail('ERR_EASR_EXPANDED_PATH_LIMIT',
        'expanded index paths exceed their strict byte limit');
    }
    expandedPathBytes += pathBytes.length;
    return { entry, ordinal, pathBytes };
  });
  prepared.sort((left, right) => Buffer.compare(left.pathBytes, right.pathBytes));
  for (let index = 1; index < prepared.length; index++) {
    if (prepared[index - 1].pathBytes.equals(prepared[index].pathBytes)) {
      fail('ERR_EASR_DUPLICATE_PATH', 'duplicate index path');
    }
  }

  let declaredEncoderChunkCount = 0;
  for (const item of prepared) {
    const entry = item.entry;
    if (!entry || entry.type !== 'file' || entry.unpacked ||
        !Array.isArray(entry.chunks)) {
      continue;
    }
    declaredEncoderChunkCount += entry.chunks.length;
    if (declaredEncoderChunkCount > MAX_ENCODER_CHUNK_COUNT) {
      fail('ERR_EASR_CHUNK_LIMIT', 'too many payload chunks');
    }
  }

  const entries = prepared.map((item, fileOrdinal) =>
    normalizeEntryForEncoding(
      item.entry,
      blockSize,
      fileOrdinal,
      item.pathBytes
    ));
  validateTree(entries);

  const entryParts = [];
  const encoderChunkCount = entries.reduce(
    (total, entry) => total +
      (entry.type === 'file' && !entry.unpacked ? entry.chunks.length : 0),
    0
  );
  if (encoderChunkCount > MAX_ENCODER_CHUNK_COUNT) {
    fail('ERR_EASR_CHUNK_LIMIT', 'too many payload chunks');
  }
  const chunkDigests = Buffer.allocUnsafe(encoderChunkCount * DIGEST_SIZE);
  const chunks = [];
  let previousPath = Buffer.alloc(0);
  let payloadSize = 0;

  for (const entry of entries) {
    const prefixLength = commonPrefixLength(previousPath, entry.pathBytes);
    const suffix = entry.pathBytes.subarray(prefixLength);
    entryParts.push(
      encodeUVarint(prefixLength),
      encodeUVarint(suffix.length),
      suffix,
      Buffer.from([entry.flags])
    );
    previousPath = entry.pathBytes;

    if (entry.type === 'symlink') {
      entryParts.push(
        encodeUVarint(entry.targetBytes.length),
        entry.targetBytes
      );
      continue;
    }
    if (entry.type !== 'file') continue;

    entryParts.push(encodeUVarint(entry.size));
    if (entry.unpacked) {
      entryParts.push(entry.digest);
      continue;
    }

    for (const chunk of entry.chunks) {
      entryParts.push(encodeUVarint(chunk.descriptor));
      const ordinal = chunks.length;
      chunk.digest.copy(chunkDigests, ordinal * DIGEST_SIZE);
      chunks.push({
        ordinal,
        fileOrdinal: entry.fileOrdinal,
        chunkInFile: chunk.chunkInFile,
        logicalOffset: chunk.chunkInFile * blockSize,
        plainSize: chunk.plainSize,
        storedSize: chunk.storedSize,
        codec: chunk.codec,
        entryFlags: entry.flags,
        payloadOffset: payloadSize
      });
      payloadSize += chunk.storedSize;
      if (!Number.isSafeInteger(payloadSize)) {
        fail('ERR_EASR_PAYLOAD_SIZE', 'payload exceeds its strict limit');
      }
    }
  }

  const header = Buffer.concat([
    INDEX_MAGIC,
    Buffer.from([
      INDEX_VERSION,
      0,
      optionalFlags,
      blockSizeLog2
    ]),
    encodeUVarint(entries.length),
    encodeUVarint(chunks.length)
  ]);
  const indexCore = Buffer.concat([header, ...entryParts]);
  const finalIndexSize = indexCore.length + chunks.length * TAG_SIZE;
  if (finalIndexSize > MAX_INDEX_SIZE) {
    fail('ERR_EASR_INDEX_LIMIT', 'index exceeds its strict byte limit');
  }
  if (BigInt(payloadSize) + BigInt(SUPERBLOCK_SIZE + finalIndexSize) >
      MAX_SAFE_INTEGER) {
    fail('ERR_EASR_PAYLOAD_SIZE', 'archive exceeds its strict size limit');
  }

  const state = {
    dataKeyId,
    epoch,
    indexCore,
    finalIndexSize,
    entryCount: entries.length,
    chunks,
    chunkDigests,
    payloadSize,
    blockSize,
    blockSizeLog2,
    archiveId: null,
    chunkCollection: null
  };
  state.archiveId = computeArchiveIdFromCore(state);
  state.chunkCollection = makeLazyChunkCollection(state);
  return makeArchivePlanView(state);
};

const decodeIndex = (buffer, options = {}) => {
  requireBuffer(buffer, undefined, 'index');
  if (buffer.length > MAX_INDEX_SIZE) {
    fail('ERR_EASR_INDEX_LIMIT', 'index exceeds its strict byte limit');
  }
  if (buffer.length < INDEX_HEADER_SIZE ||
      !buffer.subarray(0, 4).equals(INDEX_MAGIC)) {
    fail('ERR_EASR_INDEX_MAGIC', 'invalid compact index magic');
  }
  if (buffer[4] !== INDEX_VERSION) {
    fail('ERR_EASR_INDEX_VERSION', 'unsupported compact index version');
  }
  if (buffer[INDEX_CRITICAL_FLAGS_OFFSET] !== 0) {
    fail('ERR_EASR_CRITICAL_FLAGS', 'unknown critical index flags');
  }
  const blockSizeLog2 = buffer[7];
  if (blockSizeLog2 < MIN_BLOCK_SIZE_LOG2 ||
      blockSizeLog2 > MAX_BLOCK_SIZE_LOG2) {
    fail('ERR_EASR_BLOCK_SIZE', 'block size exponent is outside its limit');
  }
  const blockSize = 2 ** blockSizeLog2;

  const reader = new IndexReader(buffer);
  reader.offset = INDEX_HEADER_SIZE;
  const entryCount = reader.readVarint(
    MAX_ENTRY_COUNT,
    'ERR_EASR_ENTRY_LIMIT'
  );
  const declaredChunkCount = reader.readVarint(
    MAX_CHUNK_COUNT,
    'ERR_EASR_CHUNK_LIMIT'
  );

  const entries = [];
  const chunks = [];
  let previousPathBytes = Buffer.alloc(0);
  let expandedPathBytes = 0;
  let payloadSize = 0;

  for (let fileOrdinal = 0; fileOrdinal < entryCount; fileOrdinal++) {
    const prefixLength = reader.readVarint(
      MAX_PATH_BYTES,
      'ERR_EASR_NON_CANONICAL_PREFIX'
    );
    const suffixLength = reader.readVarint(
      MAX_PATH_BYTES,
      'ERR_EASR_NON_CANONICAL_PATH'
    );
    if (prefixLength > previousPathBytes.length ||
        prefixLength + suffixLength > MAX_PATH_BYTES) {
      fail('ERR_EASR_NON_CANONICAL_PREFIX', 'invalid path prefix length');
    }
    const pathLength = prefixLength + suffixLength;
    if (expandedPathBytes > MAX_EXPANDED_PATH_BYTES - pathLength) {
      fail('ERR_EASR_EXPANDED_PATH_LIMIT',
        'expanded index paths exceed their strict byte limit');
    }
    expandedPathBytes += pathLength;
    const suffix = reader.readBytes(suffixLength);
    const pathBytes = Buffer.concat([
      previousPathBytes.subarray(0, prefixLength),
      suffix
    ]);
    const path = decodeUtf8(pathBytes);
    validateCanonicalPath(path);

    const comparison = fileOrdinal === 0
      ? 1
      : Buffer.compare(pathBytes, previousPathBytes);
    if (fileOrdinal > 0 && comparison === 0) {
      fail('ERR_EASR_DUPLICATE_PATH', 'duplicate index path');
    }
    if (fileOrdinal > 0 && comparison < 0) {
      fail('ERR_EASR_PATH_ORDER', 'index paths are not bytewise sorted');
    }
    const canonicalPrefix = fileOrdinal === 0
      ? 0
      : commonPrefixLength(previousPathBytes, pathBytes);
    if (prefixLength !== canonicalPrefix) {
      fail('ERR_EASR_NON_CANONICAL_PREFIX',
        'path prefix is not the longest common prefix');
    }

    const flags = reader.readByte();
    const type = entryTypeFromFlags(flags);
    const entry = {
      path,
      type,
      executable: (flags & ENTRY_EXECUTABLE) !== 0,
      unpacked: (flags & ENTRY_UNPACKED) !== 0,
      flags,
      fileOrdinal
    };
    previousPathBytes = pathBytes;

    if (type === 'symlink') {
      const targetLength = reader.readVarint(
        MAX_PATH_BYTES,
        'ERR_EASR_NON_CANONICAL_PATH'
      );
      const target = decodeUtf8(reader.readBytes(targetLength));
      validateCanonicalPath(target);
      entry.target = target;
      entries.push(entry);
      continue;
    }
    if (type !== 'file') {
      entries.push(entry);
      continue;
    }

    const size = reader.readVarint(
      Number.MAX_SAFE_INTEGER,
      'ERR_EASR_FILE_SIZE'
    );
    entry.size = size;
    if (entry.unpacked) {
      entry.digest = Buffer.from(reader.readBytes(DIGEST_SIZE));
      entries.push(entry);
      continue;
    }

    const chunkCount = size === 0
      ? 0
      : Math.floor((size - 1) / blockSize) + 1;
    if (chunks.length + chunkCount > declaredChunkCount ||
        chunks.length + chunkCount > MAX_CHUNK_COUNT) {
      fail('ERR_EASR_CHUNK_COUNT', 'chunk count does not match index header');
    }
    entry.firstChunk = chunks.length;
    entry.chunkCount = chunkCount;
    for (let chunkInFile = 0; chunkInFile < chunkCount; chunkInFile++) {
      const plainSize = Math.min(
        blockSize,
        size - chunkInFile * blockSize
      );
      const descriptor = reader.readVarint(
        blockSize,
        'ERR_EASR_CHUNK_SIZE'
      );
      const codec = descriptor === 0 ? CODEC_RAW : CODEC_DEFLATE_RAW;
      const storedSize = descriptor === 0 ? plainSize : descriptor;
      if (codec === CODEC_DEFLATE_RAW &&
          (storedSize === 0 || storedSize >= plainSize)) {
        fail('ERR_EASR_CHUNK_SIZE',
          'compressed chunk must be smaller than plaintext');
      }
      if (payloadSize > Number.MAX_SAFE_INTEGER - storedSize) {
        fail('ERR_EASR_PAYLOAD_SIZE', 'payload exceeds its strict limit');
      }
      chunks.push({
        ordinal: chunks.length,
        fileOrdinal,
        chunkInFile,
        logicalOffset: chunkInFile * blockSize,
        plainSize,
        storedSize,
        codec,
        codecName: codec === CODEC_RAW ? 'raw' : 'deflate-raw',
        entryFlags: flags,
        payloadOffset: payloadSize,
        tag: null
      });
      payloadSize += storedSize;
    }
    entries.push(entry);
  }

  if (chunks.length !== declaredChunkCount) {
    fail('ERR_EASR_CHUNK_COUNT', 'chunk count does not match index header');
  }
  const tagBytes = declaredChunkCount * TAG_SIZE;
  if (reader.remaining() < tagBytes) {
    fail('ERR_EASR_TRUNCATED', 'truncated AES-GCM tag table');
  }
  for (const chunk of chunks) {
    chunk.tag = reader.readBytes(TAG_SIZE);
  }
  if (reader.remaining() !== 0) {
    fail('ERR_EASR_TRAILING_DATA', 'trailing compact index bytes');
  }

  if (options.expectedPayloadSize !== undefined) {
    const expected = toUnsignedBigInt(
      options.expectedPayloadSize,
      MAX_SAFE_INTEGER,
      'ERR_EASR_PAYLOAD_SIZE'
    );
    if (BigInt(payloadSize) !== expected) {
      fail('ERR_EASR_PAYLOAD_SIZE',
        'chunk lengths do not equal signed payload size');
    }
  }
  validateTree(entries);

  return {
    entries,
    chunks,
    entryCount,
    chunkCount: declaredChunkCount,
    tagBytes,
    payloadSize,
    blockSize,
    blockSizeLog2,
    optionalFlags: buffer[6]
  };
};

// The archive id is computed before encryption. The index core ends immediately
// before the fixed tag table, so it commits to paths, flags, block geometry,
// codecs, sizes, and the implied payload layout without a circular dependency
// on GCM tags. Each digest is SHA-256(stored plaintext chunk), after optional
// deterministic compression and before encryption, in global ordinal order.
// Consequently any changed plaintext, layout, key id, or epoch changes the
// per-archive HKDF key. Ordinal-derived nonces are unique under that key.
const computeArchiveIdFromCore = (state) => {
  const indexCoreSize = state.indexCore.length;
  const indexCoreSizeBytes = Buffer.alloc(8);
  indexCoreSizeBytes.writeBigUInt64LE(BigInt(indexCoreSize));
  const hash = crypto.createHash('sha256')
    .update(ARCHIVE_ID_DOMAIN)
    .update(state.dataKeyId);
  const epochBytes = Buffer.alloc(8);
  epochBytes.writeBigUInt64LE(state.epoch);
  hash.update(epochBytes)
    .update(indexCoreSizeBytes)
    .update(state.indexCore);
  if (state.chunkDigests) {
    hash.update(state.chunkDigests);
  } else {
    for (const chunk of state.chunks) hash.update(chunk.digest);
  }
  return hash.digest();
};

const classifyArchive = (buffer) => {
  requireBuffer(buffer, undefined, 'archive prefix');
  if (buffer.length < MAGIC.length ||
      !buffer.subarray(0, MAGIC.length).equals(MAGIC)) {
    return ArchiveKind.STANDARD_ASAR;
  }
  if (buffer.length < 8) {
    fail('ERR_EASR_TRUNCATED', 'truncated EASR version');
  }
  const version = buffer.readUInt32LE(4);
  if (version === 1) return ArchiveKind.EASR_V1;
  if (version === FORMAT_VERSION) return ArchiveKind.EASR_V2;
  fail('ERR_EASR_UNSUPPORTED_VERSION',
    'unsupported EASR version; never fall back to standard ASAR');
};

const parseSuperblock = (buffer) => {
  requireBuffer(buffer, undefined, 'superblock');
  const kind = classifyArchive(buffer);
  if (kind !== ArchiveKind.EASR_V2) {
    fail('ERR_EASR_NOT_V2', 'archive is not EASR v2');
  }
  if (buffer.length < SUPERBLOCK_SIZE) {
    fail('ERR_EASR_TRUNCATED', 'truncated EASR v2 superblock');
  }
  if (buffer.length !== SUPERBLOCK_SIZE) {
    fail('ERR_EASR_SUPERBLOCK_SIZE',
      'superblock parser requires an exact 200-byte slice');
  }
  if (buffer.readUInt16LE(8) !== SUPERBLOCK_SIZE) {
    fail('ERR_EASR_SUPERBLOCK_SIZE', 'non-canonical superblock size');
  }
  if (buffer[10] !== SIGNATURE_ALGORITHM_ED25519 ||
      buffer[11] !== DATA_ALGORITHM_AES_256_GCM) {
    fail('ERR_EASR_ALGORITHM', 'unsupported EASR v2 algorithm');
  }
  const flags = buffer.readUInt32LE(SUPERBLOCK_FLAGS_OFFSET);
  if ((flags & 0xffff0000) !== 0) {
    fail('ERR_EASR_CRITICAL_FLAGS', 'unknown critical superblock flags');
  }
  const indexSize = buffer.readUInt32LE(SUPERBLOCK_INDEX_SIZE_OFFSET);
  if (indexSize < INDEX_HEADER_SIZE || indexSize > MAX_INDEX_SIZE) {
    fail('ERR_EASR_INDEX_LIMIT', 'signed index size is outside its limit');
  }
  if (buffer.readUInt32LE(SUPERBLOCK_RESERVED_OFFSET) !== 0) {
    fail('ERR_EASR_RESERVED', 'reserved superblock bytes must be zero');
  }
  const payloadSizeBig = buffer.readBigUInt64LE(
    SUPERBLOCK_PAYLOAD_SIZE_OFFSET
  );
  if (payloadSizeBig > MAX_SAFE_INTEGER ||
      payloadSizeBig + BigInt(SUPERBLOCK_SIZE + indexSize) >
        MAX_SAFE_INTEGER) {
    fail('ERR_EASR_PAYLOAD_SIZE', 'payload exceeds its strict limit');
  }

  return {
    version: FORMAT_VERSION,
    superblockSize: SUPERBLOCK_SIZE,
    signatureAlgorithm: buffer[10],
    dataAlgorithm: buffer[11],
    optionalFlags: flags & 0xffff,
    indexSize,
    payloadSize: Number(payloadSizeBig),
    epoch: buffer.readBigUInt64LE(SUPERBLOCK_EPOCH_OFFSET),
    dataKeyId: Buffer.from(buffer.subarray(
      SUPERBLOCK_DATA_KEY_ID_OFFSET,
      SUPERBLOCK_DATA_KEY_ID_OFFSET + KEY_ID_SIZE
    )),
    signingKeyId: Buffer.from(buffer.subarray(
      SUPERBLOCK_SIGNING_KEY_ID_OFFSET,
      SUPERBLOCK_SIGNING_KEY_ID_OFFSET + KEY_ID_SIZE
    )),
    archiveId: Buffer.from(buffer.subarray(
      SUPERBLOCK_ARCHIVE_ID_OFFSET,
      SUPERBLOCK_ARCHIVE_ID_OFFSET + ARCHIVE_ID_SIZE
    )),
    indexHash: Buffer.from(buffer.subarray(
      SUPERBLOCK_INDEX_HASH_OFFSET,
      SUPERBLOCK_INDEX_HASH_OFFSET + INDEX_HASH_SIZE
    )),
    signature: Buffer.from(buffer.subarray(
      SIGNATURE_OFFSET,
      SIGNATURE_OFFSET + SIGNATURE_SIZE
    ))
  };
};

const signatureMessage = (superblock) => Buffer.concat([
  SIGNATURE_DOMAIN,
  superblock.subarray(0, SIGNATURE_OFFSET)
]);

const asPrivateKey = (key) => {
  let privateKey;
  if (key && key.type === 'private') {
    privateKey = key;
  } else {
    try {
      privateKey = crypto.createPrivateKey(key);
    } catch (error) {
      fail('ERR_EASR_SIGNING_KEY', 'invalid signing private key');
    }
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    fail('ERR_EASR_SIGNING_KEY', 'signing key must be Ed25519');
  }
  return privateKey;
};

const asPublicKey = (key) => {
  if (!(key instanceof crypto.KeyObject) || key.type !== 'public') {
    fail('ERR_EASR_SIGNING_KEY',
      'signing key resolver must return a public KeyObject');
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    fail('ERR_EASR_SIGNING_KEY', 'signing key must be Ed25519');
  }
  return key;
};

const keyIdDigest = (domain, material) => Buffer.from(
  crypto.createHash('sha256')
    .update(domain)
    .update(material)
    .digest()
    .subarray(0, KEY_ID_SIZE)
);

const deriveDataKeyId = (masterKey) => {
  requireBuffer(masterKey, 32, 'AES-256 master key');
  if (!masterKey.some(byte => byte !== 0)) {
    fail('ERR_EASR_KEY_ID', 'AES-256 master key must not be all zero');
  }
  return keyIdDigest(DATA_KEY_ID_DOMAIN, masterKey);
};

const deriveSigningKeyId = (key) => {
  let publicKey;
  if (key && key.type === 'private') {
    publicKey = crypto.createPublicKey(asPrivateKey(key));
  } else {
    publicKey = asPublicKey(key);
  }
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  return keyIdDigest(SIGNING_KEY_ID_DOMAIN, spki);
};

const encodeSuperblock = (state, index, options) => {
  if (!Buffer.isBuffer(index) ||
      index.length < INDEX_HEADER_SIZE ||
      index.length > MAX_INDEX_SIZE) {
    fail('ERR_EASR_INDEX_LIMIT', 'signed index size is outside its limit');
  }
  // `index` is assembled below from this module's already validated,
  // canonical plan. Decoding it again would temporarily allocate the full
  // entry/chunk object graph at the encoder's peak memory point.
  requireNonZeroBuffer(options.signingKeyId, KEY_ID_SIZE, 'signing key id');
  const privateKey = asPrivateKey(options.privateKey);
  const derivedSigningKeyId = deriveSigningKeyId(privateKey);
  if (!crypto.timingSafeEqual(derivedSigningKeyId, options.signingKeyId)) {
    fail('ERR_EASR_KEY_ID',
      'signing key id does not match the canonical public key');
  }
  const optionalFlags = options.optionalFlags || 0;
  if (!Number.isInteger(optionalFlags) ||
      optionalFlags < 0 || optionalFlags > 0xffff) {
    fail('ERR_EASR_FIELD', 'superblock optional flags are invalid');
  }
  if (options.criticalFlags) {
    fail('ERR_EASR_CRITICAL_FLAGS', 'unknown critical superblock flags');
  }

  const superblock = Buffer.alloc(SUPERBLOCK_SIZE);
  MAGIC.copy(superblock, 0);
  superblock.writeUInt32LE(FORMAT_VERSION, 4);
  superblock.writeUInt16LE(SUPERBLOCK_SIZE, 8);
  superblock[10] = SIGNATURE_ALGORITHM_ED25519;
  superblock[11] = DATA_ALGORITHM_AES_256_GCM;
  superblock.writeUInt32LE(optionalFlags, SUPERBLOCK_FLAGS_OFFSET);
  superblock.writeUInt32LE(
    index.length,
    SUPERBLOCK_INDEX_SIZE_OFFSET
  );
  superblock.writeBigUInt64LE(
    BigInt(state.payloadSize),
    SUPERBLOCK_PAYLOAD_SIZE_OFFSET
  );
  superblock.writeBigUInt64LE(state.epoch, SUPERBLOCK_EPOCH_OFFSET);
  state.dataKeyId.copy(superblock, SUPERBLOCK_DATA_KEY_ID_OFFSET);
  options.signingKeyId.copy(superblock, SUPERBLOCK_SIGNING_KEY_ID_OFFSET);
  state.archiveId.copy(superblock, SUPERBLOCK_ARCHIVE_ID_OFFSET);
  crypto.createHash('sha256').update(index).digest().copy(
    superblock,
    SUPERBLOCK_INDEX_HASH_OFFSET
  );

  const signature = crypto.sign(
    null,
    signatureMessage(superblock),
    privateKey
  );
  if (signature.length !== SIGNATURE_SIZE) {
    fail('ERR_EASR_SIGNATURE', 'unexpected Ed25519 signature size');
  }
  signature.copy(superblock, SIGNATURE_OFFSET);
  return superblock;
};

const finalizeArchive = (plan, options) => {
  const state = archivePlanStates.get(plan);
  if (!state) {
    fail('ERR_EASR_ARCHIVE_PLAN', 'a trusted archive plan is required');
  }
  if (!options ||
      (!Array.isArray(options.tags) && !Buffer.isBuffer(options.tags))) {
    fail('ERR_EASR_FIELD', 'one final AES-GCM tag per chunk is required');
  }
  if (options.archiveId !== undefined || options.dataKeyId !== undefined ||
      options.epoch !== undefined || options.index !== undefined) {
    fail('ERR_EASR_ARCHIVE_PLAN',
      'finalization cannot override archive identity or canonical index');
  }
  const tagCount = Buffer.isBuffer(options.tags)
    ? options.tags.length / TAG_SIZE
    : options.tags.length;
  if (!Number.isInteger(tagCount) || tagCount !== state.chunks.length) {
    fail('ERR_EASR_CHUNK_COUNT', 'final tag count does not match archive plan');
  }

  const recomputedId = computeArchiveIdFromCore(state);
  if (!crypto.timingSafeEqual(recomputedId, state.archiveId)) {
    fail('ERR_EASR_ARCHIVE_ID',
      'archive plan identity changed before finalization');
  }
  const index = Buffer.allocUnsafe(state.finalIndexSize);
  state.indexCore.copy(index, 0);
  if (Buffer.isBuffer(options.tags)) {
    options.tags.copy(index, state.indexCore.length);
  } else {
    for (let ordinal = 0; ordinal < options.tags.length; ordinal++) {
      const tag = requireBuffer(options.tags[ordinal], TAG_SIZE, 'chunk tag');
      tag.copy(index, state.indexCore.length + ordinal * TAG_SIZE);
    }
  }
  if (index.length !== state.finalIndexSize ||
      index.length > MAX_INDEX_SIZE) {
    fail('ERR_EASR_INDEX_LIMIT', 'final index exceeds its authenticated budget');
  }
  const superblock = encodeSuperblock(state, index, options);
  return Object.freeze({
    superblock,
    index,
    payloadSize: state.payloadSize,
    payloadOffset: SUPERBLOCK_SIZE + index.length,
    archiveSize: SUPERBLOCK_SIZE + index.length + state.payloadSize,
    archiveId: Buffer.from(state.archiveId),
    entryCount: state.entryCount,
    chunkCount: state.chunks.length,
    tagBytes: state.chunks.length * TAG_SIZE
  });
};

const makeVerifiedHeaderView = (state) => {
  const header = {};
  Object.defineProperties(header, {
    version: { enumerable: true, value: state.version },
    superblockSize: { enumerable: true, value: state.superblockSize },
    signatureAlgorithm: { enumerable: true, value: state.signatureAlgorithm },
    dataAlgorithm: { enumerable: true, value: state.dataAlgorithm },
    optionalFlags: { enumerable: true, value: state.optionalFlags },
    indexSize: { enumerable: true, value: state.indexSize },
    payloadSize: { enumerable: true, value: state.payloadSize },
    epoch: { enumerable: true, value: state.epoch },
    dataKeyId: {
      enumerable: true,
      get: () => Buffer.from(state.dataKeyId)
    },
    signingKeyId: {
      enumerable: true,
      get: () => Buffer.from(state.signingKeyId)
    },
    archiveId: {
      enumerable: true,
      get: () => Buffer.from(state.archiveId)
    },
    indexHash: {
      enumerable: true,
      get: () => Buffer.from(state.indexHash)
    }
  });
  Object.freeze(header);
  verifiedHeaderStates.set(header, state);
  return header;
};

const verifySuperblock = (superblock, options = {}) => {
  const parsed = parseSuperblock(superblock);
  requireNonZeroBuffer(parsed.dataKeyId, KEY_ID_SIZE, 'data key id');
  requireNonZeroBuffer(parsed.signingKeyId, KEY_ID_SIZE, 'signing key id');
  requireNonZeroBuffer(parsed.archiveId, ARCHIVE_ID_SIZE, 'archive id');
  if (typeof options.resolveSigningKey !== 'function') {
    fail('ERR_EASR_SIGNING_KEY', 'signing key resolver is required');
  }
  const key = options.resolveSigningKey(Buffer.from(parsed.signingKeyId));
  if (!key) fail('ERR_EASR_SIGNING_KEY', 'unknown signing key id');
  const publicKey = asPublicKey(key);
  const derivedSigningKeyId = deriveSigningKeyId(publicKey);
  if (!crypto.timingSafeEqual(derivedSigningKeyId, parsed.signingKeyId)) {
    fail('ERR_EASR_KEY_ID',
      'resolved public key does not match the signed key id');
  }
  if (!crypto.verify(
    null,
    signatureMessage(superblock),
    publicKey,
    parsed.signature
  )) {
    fail('ERR_EASR_SIGNATURE', 'invalid signed superblock');
  }

  const minimumEpoch = options.minimumEpoch === undefined
    ? BigInt(0)
    : toUnsignedBigInt(options.minimumEpoch, UINT64_MAX, 'ERR_EASR_EPOCH');
  if (parsed.epoch < minimumEpoch) {
    fail('ERR_EASR_ROLLBACK', 'archive epoch is below trusted minimum');
  }
  const archiveSize = toUnsignedBigInt(
    options.archiveSize,
    MAX_SAFE_INTEGER,
    'ERR_EASR_ARCHIVE_SIZE'
  );
  const expectedArchiveSize = BigInt(SUPERBLOCK_SIZE) +
    BigInt(parsed.indexSize) + BigInt(parsed.payloadSize);
  if (archiveSize !== expectedArchiveSize) {
    fail('ERR_EASR_ARCHIVE_SIZE',
      'archive has truncation or trailing unsigned bytes');
  }
  return makeVerifiedHeaderView(parsed);
};

const createIndexStreamVerifier = (verifiedHeader) => {
  const state = verifiedHeaderStates.get(verifiedHeader);
  if (!state) {
    fail('ERR_EASR_UNTRUSTED_HEADER',
      'index streaming requires a verified superblock');
  }
  const hash = crypto.createHash('sha256');
  let receivedSize = 0;
  let finished = false;
  const verifier = {
    update: bytes => {
      if (finished) {
        fail('ERR_EASR_INDEX_STATE', 'index verifier is already finalized');
      }
      requireBuffer(bytes, undefined, 'index stream bytes');
      if (bytes.length > state.indexSize - receivedSize) {
        fail('ERR_EASR_INDEX_SIZE',
          'index stream exceeds authenticated size');
      }
      hash.update(bytes);
      receivedSize += bytes.length;
      return verifier;
    },
    finalize: () => {
      if (finished) {
        fail('ERR_EASR_INDEX_STATE', 'index verifier is already finalized');
      }
      finished = true;
      if (receivedSize !== state.indexSize) {
        fail('ERR_EASR_INDEX_SIZE',
          'index stream is shorter than authenticated size');
      }
      const actual = hash.digest();
      if (!crypto.timingSafeEqual(actual, state.indexHash)) {
        fail('ERR_EASR_INDEX_HASH', 'signed index hash mismatch');
      }
      return true;
    }
  };
  Object.defineProperties(verifier, {
    expectedSize: { enumerable: true, value: state.indexSize },
    receivedSize: { enumerable: true, get: () => receivedSize }
  });
  return Object.freeze(verifier);
};

const verifyIndex = (verifiedHeader, index) => {
  const state = verifiedHeaderStates.get(verifiedHeader);
  if (!state) {
    fail('ERR_EASR_UNTRUSTED_HEADER',
      'index parsing requires a verified superblock');
  }
  requireBuffer(index, undefined, 'signed index');
  const stream = createIndexStreamVerifier(verifiedHeader);
  const streamChunkSize = 64 * 1024;
  for (let offset = 0; offset < index.length; offset += streamChunkSize) {
    stream.update(index.subarray(
      offset,
      Math.min(offset + streamChunkSize, index.length)
    ));
  }
  stream.finalize();
  const decoded = decodeIndex(index, {
    expectedPayloadSize: state.payloadSize
  });
  decoded.chunks = Object.freeze(
    decoded.chunks.map(chunk => makeChunkContext(state, chunk))
  );
  return decoded;
};

const verifyEnvelope = (superblock, index, options = {}) => {
  // Signature verification deliberately happens before touching index bytes.
  // A caller can instead use verifySuperblock/createIndexStreamVerifier to
  // read the now-authenticated indexSize sequentially from disk.
  const header = verifySuperblock(superblock, options);
  const decodedIndex = verifyIndex(header, index);
  const state = verifiedHeaderStates.get(header);
  return {
    header,
    index: decodedIndex,
    payloadOffset: SUPERBLOCK_SIZE + state.indexSize,
    archiveSize: SUPERBLOCK_SIZE + state.indexSize + state.payloadSize,
    signatureVerifications: 1
  };
};

const trustedIdentityState = source => {
  const state = archivePlanStates.get(source) ||
    verifiedHeaderStates.get(source);
  if (!state) {
    fail('ERR_EASR_UNTRUSTED_HEADER',
      'cryptographic derivation requires a plan or verified superblock');
  }
  return state;
};

const deriveDataKey = (masterKey, trustedSource) => {
  requireBuffer(masterKey, 32, 'AES-256 master key');
  const state = trustedIdentityState(trustedSource);
  const derivedDataKeyId = deriveDataKeyId(masterKey);
  if (!crypto.timingSafeEqual(derivedDataKeyId, state.dataKeyId)) {
    fail('ERR_EASR_KEY_ID',
      'data key does not match the authenticated data key id');
  }
  const epochBytes = Buffer.alloc(8);
  epochBytes.writeBigUInt64LE(state.epoch);
  return Buffer.from(crypto.hkdfSync(
    'sha256',
    masterKey,
    state.archiveId,
    Buffer.concat([DATA_KEY_DOMAIN, state.dataKeyId, epochBytes]),
    32
  ));
};

const deriveChunkNonce = (ordinal) => {
  const chunkOrdinal = toUnsignedBigInt(
    ordinal,
    UINT64_MAX,
    'ERR_EASR_CHUNK_LIMIT'
  );
  const nonce = Buffer.alloc(12);
  NONCE_DOMAIN.copy(nonce, 0);
  nonce.writeBigUInt64LE(chunkOrdinal, 4);
  return nonce;
};

const requireUInt32 = (value, name) => {
  const integer = toUnsignedBigInt(value, UINT32_MAX, 'ERR_EASR_FIELD');
  return Number(integer);
};

const buildChunkAad = (trustedSource, chunkContext) => {
  const state = trustedIdentityState(trustedSource);
  const contextState = chunkContextStates.get(chunkContext);
  if (!contextState || contextState.ownerState !== state) {
    fail('ERR_EASR_CHUNK_CONTEXT',
      'AAD requires a chunk context from the same trusted archive');
  }
  const chunk = contextState.chunk;
  const epoch = state.epoch;
  const ordinal = toUnsignedBigInt(
    chunk.ordinal,
    UINT64_MAX,
    'ERR_EASR_CHUNK_LIMIT'
  );
  const logicalOffset = toUnsignedBigInt(
    chunk.logicalOffset,
    UINT64_MAX,
    'ERR_EASR_FILE_SIZE'
  );
  const fileOrdinal = requireUInt32(chunk.fileOrdinal, 'file ordinal');
  const chunkInFile = requireUInt32(chunk.chunkInFile, 'file chunk ordinal');
  const plainSize = requireUInt32(chunk.plainSize, 'plain chunk size');
  const storedSize = requireUInt32(chunk.storedSize, 'stored chunk size');
  if (chunk.codec !== CODEC_RAW && chunk.codec !== CODEC_DEFLATE_RAW) {
    fail('ERR_EASR_CODEC', 'unknown chunk codec');
  }
  if (!Number.isInteger(chunk.entryFlags) ||
      chunk.entryFlags < 0 || chunk.entryFlags > 0xff) {
    fail('ERR_EASR_ENTRY_FLAGS', 'invalid entry flags in AAD');
  }

  const aad = Buffer.alloc(108);
  AAD_DOMAIN.copy(aad, 0);
  state.archiveId.copy(aad, 16);
  state.dataKeyId.copy(aad, 48);
  aad.writeBigUInt64LE(epoch, 64);
  aad.writeUInt32LE(fileOrdinal, 72);
  aad.writeUInt32LE(chunkInFile, 76);
  aad.writeBigUInt64LE(ordinal, 80);
  aad.writeBigUInt64LE(logicalOffset, 88);
  aad.writeUInt32LE(plainSize, 96);
  aad.writeUInt32LE(storedSize, 100);
  aad[104] = chunk.codec;
  aad[105] = chunk.entryFlags;
  return aad;
};

module.exports = {
  ArchiveKind,
  EasrFormatError,
  buildChunkAad,
  classifyArchive,
  createArchivePlan,
  createIndexStreamVerifier,
  decodeIndex,
  decodeUVarint,
  deriveChunkNonce,
  deriveDataKey,
  deriveDataKeyId,
  deriveSigningKeyId,
  encodeUVarint,
  finalizeArchive,
  parseSuperblock,
  verifyEnvelope,
  verifyIndex,
  verifySuperblock,
  constants: Object.freeze({
    ARCHIVE_ID_SIZE,
    CODEC_DEFLATE_RAW,
    CODEC_RAW,
    DEFAULT_BLOCK_SIZE_LOG2,
    DIGEST_SIZE,
    ENTRY_DIRECTORY,
    ENTRY_EXECUTABLE,
    ENTRY_FILE,
    ENTRY_SYMLINK,
    ENTRY_UNPACKED,
    FORMAT_VERSION,
    INDEX_CRITICAL_FLAGS_OFFSET,
    INDEX_HEADER_SIZE,
    INDEX_VERSION,
    KEY_ID_SIZE,
    MAX_CHUNK_COUNT,
    MAX_ENCODER_CHUNK_COUNT,
    MAX_ENTRY_COUNT,
    MAX_EXPANDED_PATH_BYTES,
    MAX_INDEX_SIZE,
    MAX_PATH_BYTES,
    SIGNATURE_OFFSET,
    SIGNATURE_SIZE,
    SUPERBLOCK_FLAGS_OFFSET,
    SUPERBLOCK_SIZE,
    TAG_SIZE,
    UINT64_MAX
  })
};

#!/usr/bin/env node

/* global BigInt */

const assert = require('assert');
const crypto = require('crypto');

const format = require('./lib/easar-v2-format');

const tests = [];
const test = (name, body) => tests.push({ name, body });

const bytes = (start, length) => Buffer.from(
  Array.from({ length }, (_, index) => (start + index) & 0xff)
);

const makePrivateKey = () => crypto.createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    bytes(0, 32)
  ]),
  format: 'der',
  type: 'pkcs8'
});

const goldenChunkDigests = () => [
  crypto.createHash('sha256').update('stored-chunk-0').digest(),
  crypto.createHash('sha256').update('stored-chunk-1').digest()
];

const goldenTags = () => [bytes(0, 16), bytes(16, 16)];

const finalizationOptions = tags => {
  const privateKey = makePrivateKey();
  return {
    tags,
    signingKeyId: format.deriveSigningKeyId(privateKey),
    privateKey
  };
};

const goldenEntries = () => [
  {
    path: 'app/native.node',
    type: 'file',
    unpacked: true,
    size: 3,
    digest: crypto.createHash('sha256').update('abc').digest()
  },
  {
    path: 'app/link',
    type: 'symlink',
    target: 'app/a.js'
  },
  {
    path: 'app/empty',
    type: 'file',
    size: 0,
    chunks: []
  },
  {
    path: 'app/a.js',
    type: 'file',
    executable: true,
    size: 70000,
    chunks: [
      {
        codec: 'raw',
        storedSize: 65536,
        digest: goldenChunkDigests()[0]
      },
      {
        codec: 'deflate-raw',
        storedSize: 1234,
        digest: goldenChunkDigests()[1]
      }
    ]
  },
  {
    path: 'app',
    type: 'directory'
  }
];

const createGoldenPlan = () => format.createArchivePlan({
  blockSizeLog2: 16,
  entries: goldenEntries(),
  dataKeyId: format.deriveDataKeyId(bytes(32, 32)),
  epoch: BigInt(7)
});

const finalizeGolden = () => {
  const plan = createGoldenPlan();
  const archive = format.finalizeArchive(
    plan,
    finalizationOptions(goldenTags())
  );
  return { plan, ...archive };
};

const createPlan = (entries, options = {}) => format.createArchivePlan({
  entries,
  blockSizeLog2: options.blockSizeLog2 || 16,
  dataKeyId: options.dataKeyId || format.deriveDataKeyId(bytes(32, 32)),
  epoch: options.epoch === undefined ? BigInt(7) : options.epoch
});

const encodeGoldenIndex = () => {
  const archive = finalizeGolden();
  return {
    buffer: archive.index,
    payloadSize: archive.payloadSize,
    chunkCount: archive.chunkCount,
    tagBytes: archive.tagBytes
  };
};

const expectCode = (body, code) => {
  assert.throws(body, error => {
    assert.strictEqual(error && error.code, code);
    return true;
  });
};

const rawIndex = (body, options = {}) => Buffer.concat([
  Buffer.from('EIDX'),
  Buffer.from([
    format.constants.INDEX_VERSION,
    options.criticalFlags || 0,
    options.optionalFlags || 0,
    options.blockSizeLog2 || 16
  ]),
  body
]);

const directoryRecord = (prefixLength, suffix) => {
  const suffixBytes = Buffer.from(suffix, 'utf8');
  return Buffer.concat([
    format.encodeUVarint(prefixLength),
    format.encodeUVarint(suffixBytes.length),
    suffixBytes,
    Buffer.from([format.constants.ENTRY_DIRECTORY])
  ]);
};

const directoryRecordBytes = (prefixLength, suffixBytes) => Buffer.concat([
  format.encodeUVarint(prefixLength),
  format.encodeUVarint(suffixBytes.length),
  suffixBytes,
  Buffer.from([format.constants.ENTRY_DIRECTORY])
]);

const commonPrefixLength = (left, right) => {
  const limit = Math.min(left.length, right.length);
  let length = 0;
  while (length < limit && left[length] === right[length]) length++;
  return length;
};

const canonicalPathOfLength = length => {
  assert(Number.isInteger(length) && length > 0);
  const segments = [];
  let remaining = length;
  while (remaining > 255) {
    segments.push('a'.repeat(254));
    remaining -= 255;
  }
  segments.push('a'.repeat(remaining));
  return segments.join('/');
};

const expandedPathBoundaryFixture = () => {
  const base = canonicalPathOfLength(
    format.constants.MAX_PATH_BYTES - 8
  );
  const entries = [];
  const parents = [];
  let parent = '';
  let total = 0;
  for (const segment of base.split('/')) {
    parent = parent.length === 0 ? segment : parent + '/' + segment;
    const entry = { path: parent, type: 'directory' };
    entries.push(entry);
    parents.push(entry);
    total += Buffer.byteLength(parent, 'utf8');
  }

  let ordinal = 0;
  const leafPath = value =>
    base + '/' + String(value).padStart(7, '0');
  while (total <= format.constants.MAX_EXPANDED_PATH_BYTES -
      format.constants.MAX_PATH_BYTES) {
    entries.push({ path: leafPath(ordinal++), type: 'directory' });
    total += format.constants.MAX_PATH_BYTES;
  }

  const remaining = format.constants.MAX_EXPANDED_PATH_BYTES - total;
  let fillerParent;
  for (let index = parents.length - 1; index >= 0; index--) {
    const segmentLength =
      remaining - Buffer.byteLength(parents[index].path) - 1;
    if (segmentLength > 0 && segmentLength <= 255) {
      fillerParent = parents[index];
      break;
    }
  }
  assert(fillerParent);
  const fillerLength = remaining - Buffer.byteLength(fillerParent.path) - 1;
  entries.push({
    path: fillerParent.path + '/' + 'b'.repeat(fillerLength),
    type: 'directory'
  });
  total += remaining;
  return { entries, nextPath: leafPath(ordinal), total };
};

test('pins minimal unsigned LEB128 encoding', () => {
  const vectors = [
    [0, '00'],
    [1, '01'],
    [127, '7f'],
    [128, '8001'],
    [16384, '808001'],
    [Number.MAX_SAFE_INTEGER, 'ffffffffffffff0f'],
    [format.constants.UINT64_MAX, 'ffffffffffffffffff01']
  ];
  for (const [value, expected] of vectors) {
    const encoded = format.encodeUVarint(value);
    assert.strictEqual(encoded.toString('hex'), expected);
    const decoded = format.decodeUVarint(encoded);
    assert.strictEqual(decoded.value, BigInt(value));
    assert.strictEqual(decoded.offset, encoded.length);
  }
});

test('rejects non-minimal, truncated, and overflowing varints', () => {
  expectCode(() => format.decodeUVarint(Buffer.from('8000', 'hex')),
    'ERR_EASR_NON_CANONICAL_VARINT');
  expectCode(() => format.decodeUVarint(Buffer.from('80', 'hex')),
    'ERR_EASR_TRUNCATED');
  expectCode(() => format.decodeUVarint(Buffer.from('ffffffffffffffffff02', 'hex')),
    'ERR_EASR_VARINT_OVERFLOW');
  expectCode(() => format.decodeUVarint(Buffer.from('8080808080808080808000', 'hex')),
    'ERR_EASR_VARINT_OVERFLOW');
});

test('pins the canonical flat prefix-compressed index bytes', () => {
  const encoded = encodeGoldenIndex();
  assert.strictEqual(encoded.payloadSize, 66770);
  assert.strictEqual(encoded.chunkCount, 2);
  assert.strictEqual(
    encoded.buffer.toString('hex'),
    '4549445801000010050200036170700003052f612e6a7305f0a20400d2090405656d707479010004046c696e6b02086170702f612e6a73040b6e61746976652e6e6f64650903ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
  );

  const decoded = format.decodeIndex(encoded.buffer, {
    expectedPayloadSize: encoded.payloadSize
  });
  assert.deepStrictEqual(
    decoded.entries.map(entry => entry.path),
    ['app', 'app/a.js', 'app/empty', 'app/link', 'app/native.node']
  );
  assert.strictEqual(decoded.chunks.length, 2);
  assert.strictEqual(decoded.chunks[0].payloadOffset, 0);
  assert.strictEqual(decoded.chunks[1].payloadOffset, 65536);
  assert.strictEqual(decoded.tagBytes, decoded.chunkCount * 16);
});

test('pins the signed superblock and verifies one signature over its index hash', () => {
  const archive = finalizeGolden();
  const { superblock, index } = archive;
  assert.strictEqual(superblock.length, format.constants.SUPERBLOCK_SIZE);
  assert.strictEqual(
    superblock.toString('hex'),
    '4541535202000000c8000101000000008600000000000000d20401000000000007000000000000009a2dd36183154807a0fd6e09034e41c1475f3595fe9b63ea820602eb047aa52cc09e919986af1c08d31dd820e1b98bc9e0ce2ba97106155d1c5c17d444d75a087f0743b63dc72f078f7e4d568e8a29d9d8b9a61231a490de78f6999c7ea652ca2418a471f01b28d9e8a1f176a8871ae38a3392539ee7e497cfc86f84c0c2b4f72d2b4f4210a7557d8880eef8c23ea91d3972a61e328cdc0b2bf9fc7afbb52408'
  );

  const publicKey = crypto.createPublicKey(makePrivateKey());
  const verified = format.verifyEnvelope(superblock, index, {
    archiveSize: archive.archiveSize,
    minimumEpoch: BigInt(7),
    resolveSigningKey: keyId => {
      assert(keyId.equals(
        format.deriveSigningKeyId(publicKey)
      ));
      return publicKey;
    }
  });
  assert.strictEqual(verified.signatureVerifications, 1);
  assert.strictEqual(verified.index.chunkCount, 2);
  assert.strictEqual(verified.payloadOffset,
    superblock.length + index.length);
});

test('pins archive id to the canonical pre-encryption plan', () => {
  const plan = createGoldenPlan();
  assert.strictEqual(plan.archiveId.toString('hex'),
    'c09e919986af1c08d31dd820e1b98bc9e0ce2ba97106155d1c5c17d444d75a08');

  const changedEntries = goldenEntries();
  changedEntries[3].chunks[1].digest = Buffer.from(
    changedEntries[3].chunks[1].digest
  );
  changedEntries[3].chunks[1].digest[0] ^= 1;
  const changed = format.createArchivePlan({
    entries: changedEntries,
    blockSizeLog2: 16,
    dataKeyId: format.deriveDataKeyId(bytes(32, 32)),
    epoch: BigInt(7)
  });
  assert(!changed.archiveId.equals(plan.archiveId));

  const changedTags = goldenTags();
  changedTags[1] = Buffer.from(changedTags[1]);
  changedTags[1][0] ^= 1;
  const finalized = format.finalizeArchive(plan, {
    tags: changedTags,
    signingKeyId: format.deriveSigningKeyId(makePrivateKey()),
    privateKey: makePrivateKey()
  });
  assert(finalized.archiveId.equals(plan.archiveId));
});

test('keeps encoder chunk metadata lazy, contiguous, and bounded', () => {
  const plan = createGoldenPlan();
  assert.strictEqual(plan.chunks.length, 2);
  assert.strictEqual(Array.isArray(plan.chunks), false);
  assert.deepStrictEqual(Object.keys(plan.chunks), ['length']);
  assert.strictEqual(plan.chunks[0].ordinal, 0);
  assert.strictEqual(Array.from(plan.chunks).length, 2);

  const arrayFinalized = format.finalizeArchive(
    plan,
    finalizationOptions(goldenTags())
  );
  const contiguousFinalized = format.finalizeArchive(
    createGoldenPlan(),
    finalizationOptions(Buffer.concat(goldenTags()))
  );
  assert(arrayFinalized.index.equals(contiguousFinalized.index));
  assert(arrayFinalized.superblock.equals(contiguousFinalized.superblock));

  const tooManyChunks = new Array(
    format.constants.MAX_ENCODER_CHUNK_COUNT + 1
  );
  expectCode(() => createPlan([{
    path: 'large.bin',
    type: 'file',
    size: tooManyChunks.length * 4096,
    chunks: tooManyChunks
  }], { blockSizeLog2: 12 }), 'ERR_EASR_CHUNK_LIMIT');
});

test('pins archive-key, derived nonce, and AAD bytes without storing a nonce', () => {
  const plan = createGoldenPlan();
  const dataKey = format.deriveDataKey(bytes(32, 32), plan);
  assert.strictEqual(dataKey.toString('hex'),
    'ad2032509406ae3d56028ee973dd7d7882f08286771324b46fd9c59feecd9905');

  const nonce0 = format.deriveChunkNonce(0);
  const nonce1 = format.deriveChunkNonce(1);
  assert.strictEqual(nonce0.toString('hex'), '454132440000000000000000');
  assert.strictEqual(nonce1.toString('hex'), '454132440100000000000000');
  assert(!nonce0.equals(nonce1));

  const aad = format.buildChunkAad(plan, plan.chunks[1]);
  assert.strictEqual(aad.toString('hex'),
    '45415352322d444154412d4141440000c09e919986af1c08d31dd820e1b98bc9e0ce2ba97106155d1c5c17d444d75a089a2dd36183154807a0fd6e09034e41c1070000000000000001000000010000000100000000000000000001000000000070110000d204000001050000');

  const untrustedHeader = format.parseSuperblock(finalizeGolden().superblock);
  expectCode(() => format.deriveDataKey(bytes(32, 32), untrustedHeader),
    'ERR_EASR_UNTRUSTED_HEADER');
});

test('sorts encoder input but rejects non-canonical and duplicate paths', () => {
  const first = encodeGoldenIndex().buffer;
  const second = format.finalizeArchive(
    createPlan(goldenEntries().reverse()),
    finalizationOptions(goldenTags())
  ).index;
  assert(first.equals(second));

  const invalidPaths = [
    '/absolute',
    'trailing/',
    'a//b',
    'a/./b',
    'a/../b',
    'a\\b',
    'a\u0000b',
    'cafe\u0301'
  ];
  for (const path of invalidPaths) {
    expectCode(() => createPlan([{ path, type: 'directory' }]),
      'ERR_EASR_NON_CANONICAL_PATH');
  }

  expectCode(() => createPlan([
    { path: 'a', type: 'directory' },
    { path: 'a', type: 'directory' }
  ]), 'ERR_EASR_DUPLICATE_PATH');
});

test('decoder rejects duplicate, unsorted, and non-maximal prefix paths', () => {
  const duplicate = rawIndex(Buffer.concat([
    format.encodeUVarint(2),
    format.encodeUVarint(0),
    directoryRecord(0, 'a'),
    directoryRecord(1, '')
  ]));
  expectCode(() => format.decodeIndex(duplicate, { expectedPayloadSize: 0 }),
    'ERR_EASR_DUPLICATE_PATH');

  const unsorted = rawIndex(Buffer.concat([
    format.encodeUVarint(2),
    format.encodeUVarint(0),
    directoryRecord(0, 'b'),
    directoryRecord(0, 'a')
  ]));
  expectCode(() => format.decodeIndex(unsorted, { expectedPayloadSize: 0 }),
    'ERR_EASR_PATH_ORDER');

  const nonMaximalPrefix = rawIndex(Buffer.concat([
    format.encodeUVarint(2),
    format.encodeUVarint(0),
    directoryRecord(0, 'app'),
    directoryRecord(2, 'p/a')
  ]));
  expectCode(() => format.decodeIndex(nonMaximalPrefix,
    { expectedPayloadSize: 0 }), 'ERR_EASR_NON_CANONICAL_PREFIX');
});

test('decoder rejects invalid UTF-8, missing parents, and unknown entry flags', () => {
  const invalidUtf8Record = Buffer.concat([
    format.encodeUVarint(0),
    format.encodeUVarint(2),
    Buffer.from([0xc0, 0x80]),
    Buffer.from([format.constants.ENTRY_DIRECTORY])
  ]);
  expectCode(() => format.decodeIndex(rawIndex(Buffer.concat([
    format.encodeUVarint(1),
    format.encodeUVarint(0),
    invalidUtf8Record
  ])), { expectedPayloadSize: 0 }), 'ERR_EASR_INVALID_UTF8');

  expectCode(() => createPlan([
    { path: 'a/b', type: 'file', size: 0, chunks: [] }
  ]), 'ERR_EASR_MISSING_PARENT');

  const unknownEntryFlag = rawIndex(Buffer.concat([
    format.encodeUVarint(1),
    format.encodeUVarint(0),
    format.encodeUVarint(0),
    format.encodeUVarint(1),
    Buffer.from('a'),
    Buffer.from([0x10])
  ]));
  expectCode(() => format.decodeIndex(unknownEntryFlag,
    { expectedPayloadSize: 0 }), 'ERR_EASR_CRITICAL_FLAGS');
});

test('rejects inconsistent chunk geometry and exact payload bounds', () => {
  expectCode(() => createPlan([
    { path: 'a', type: 'file', size: 1, chunks: [] }
  ]), 'ERR_EASR_CHUNK_COUNT');

  expectCode(() => createPlan([
    {
      path: 'a',
      type: 'file',
      size: 1,
      chunks: [{
        codec: 'deflate-raw',
        storedSize: 1,
        digest: crypto.createHash('sha256').update('x').digest()
      }]
    }
  ]), 'ERR_EASR_CHUNK_SIZE');

  const index = encodeGoldenIndex();
  expectCode(() => format.decodeIndex(index.buffer, {
    expectedPayloadSize: index.payloadSize + 1
  }), 'ERR_EASR_PAYLOAD_SIZE');
  expectCode(() => format.decodeIndex(index.buffer.subarray(0, index.buffer.length - 1), {
    expectedPayloadSize: index.payloadSize
  }), 'ERR_EASR_TRUNCATED');
  expectCode(() => format.decodeIndex(Buffer.concat([index.buffer, Buffer.from([0])]), {
    expectedPayloadSize: index.payloadSize
  }), 'ERR_EASR_TRAILING_DATA');
});

test('rejects unknown critical flags before trusting index-controlled sizes', () => {
  const index = encodeGoldenIndex();
  const criticalIndex = Buffer.from(index.buffer);
  criticalIndex[format.constants.INDEX_CRITICAL_FLAGS_OFFSET] = 1;
  expectCode(() => format.decodeIndex(criticalIndex, {
    expectedPayloadSize: index.payloadSize
  }), 'ERR_EASR_CRITICAL_FLAGS');

  const { superblock } = finalizeGolden();
  const criticalSuperblock = Buffer.from(superblock);
  criticalSuperblock[format.constants.SUPERBLOCK_FLAGS_OFFSET + 2] = 1;
  expectCode(() => format.parseSuperblock(criticalSuperblock),
    'ERR_EASR_CRITICAL_FLAGS');
});

test('rejects non-minimal and over-limit index fields before allocation', () => {
  const index = encodeGoldenIndex();
  const nonMinimalEntryCount = Buffer.concat([
    index.buffer.subarray(0, 8),
    Buffer.from([0x85, 0x00]),
    index.buffer.subarray(9)
  ]);
  expectCode(() => format.decodeIndex(nonMinimalEntryCount, {
    expectedPayloadSize: index.payloadSize
  }), 'ERR_EASR_NON_CANONICAL_VARINT');

  const excessiveEntryCount = rawIndex(Buffer.concat([
    format.encodeUVarint(format.constants.MAX_ENTRY_COUNT + 1),
    format.encodeUVarint(0)
  ]));
  expectCode(() => format.decodeIndex(excessiveEntryCount, {
    expectedPayloadSize: 0
  }), 'ERR_EASR_ENTRY_LIMIT');

  const { superblock } = finalizeGolden();
  const excessiveArchive = Buffer.from(superblock);
  excessiveArchive.writeBigUInt64LE(
    BigInt(Number.MAX_SAFE_INTEGER),
    24
  );
  expectCode(() => format.parseSuperblock(excessiveArchive),
    'ERR_EASR_PAYLOAD_SIZE');
});

test('accepts the expanded-path boundary and rejects encoder overflow', () => {
  const fixture = expandedPathBoundaryFixture();
  assert.strictEqual(
    fixture.total,
    format.constants.MAX_EXPANDED_PATH_BYTES
  );

  expectCode(() => createPlan(fixture.entries.concat([{
    path: fixture.nextPath,
    type: 'directory'
  }])), 'ERR_EASR_EXPANDED_PATH_LIMIT');

  const plan = createPlan(fixture.entries);
  assert.strictEqual(plan.entryCount, fixture.entries.length);
});

test('rejects expanded-path decoder overflow before UTF-8 decoding', () => {
  const pathLength = format.constants.MAX_PATH_BYTES;
  const acceptedCount =
    format.constants.MAX_EXPANDED_PATH_BYTES / pathLength;
  assert(Number.isInteger(acceptedCount));
  const base = canonicalPathOfLength(pathLength - 8);
  const records = [];
  let previous = Buffer.alloc(0);
  for (let ordinal = 0; ordinal < acceptedCount; ordinal++) {
    const current = Buffer.from(
      base + '/' + String(ordinal).padStart(7, '0'),
      'utf8'
    );
    assert.strictEqual(current.length, pathLength);
    const prefixLength = commonPrefixLength(previous, current);
    records.push(directoryRecordBytes(
      prefixLength,
      Buffer.from(current.subarray(prefixLength))
    ));
    previous = current;
  }

  // One invalid UTF-8 byte would normally fail decoding. It instead crosses
  // the exact 64 MiB aggregate boundary and must be rejected before decode.
  records.push(directoryRecordBytes(0, Buffer.from([0xff])));
  const index = rawIndex(Buffer.concat([
    format.encodeUVarint(acceptedCount + 1),
    format.encodeUVarint(0),
    ...records
  ]));
  expectCode(() => format.decodeIndex(index, { expectedPayloadSize: 0 }),
    'ERR_EASR_EXPANDED_PATH_LIMIT');
});

test('authenticates index and header and enforces epoch and archive length', () => {
  const archive = finalizeGolden();
  const index = {
    buffer: archive.index,
    payloadSize: archive.payloadSize
  };
  const { superblock } = archive;
  const publicKey = crypto.createPublicKey(makePrivateKey());
  const options = {
    archiveSize: archive.archiveSize,
    resolveSigningKey: () => publicKey
  };

  const changedIndex = Buffer.from(index.buffer);
  changedIndex[changedIndex.length - 1] ^= 1;
  expectCode(() => format.verifyEnvelope(superblock, changedIndex, options),
    'ERR_EASR_INDEX_HASH');

  const changedSignature = Buffer.from(superblock);
  changedSignature[format.constants.SIGNATURE_OFFSET] ^= 1;
  expectCode(() => format.verifyEnvelope(changedSignature, index.buffer, options),
    'ERR_EASR_SIGNATURE');

  expectCode(() => format.verifyEnvelope(superblock, index.buffer, {
    ...options,
    minimumEpoch: BigInt(8)
  }), 'ERR_EASR_ROLLBACK');

  expectCode(() => format.verifyEnvelope(superblock, index.buffer, {
    ...options,
    archiveSize: options.archiveSize + 1
  }), 'ERR_EASR_ARCHIVE_SIZE');

  expectCode(() => format.verifyEnvelope(superblock, index.buffer, {
    ...options,
    resolveSigningKey: () => null
  }), 'ERR_EASR_SIGNING_KEY');
});

test('keeps standard ASAR, EASR v1, v2, and unknown EASR disjoint', () => {
  assert.strictEqual(
    format.classifyArchive(Buffer.from('0400000000000000', 'hex')),
    format.ArchiveKind.STANDARD_ASAR
  );

  const v1 = Buffer.alloc(8);
  v1.write('EASR', 0, 'ascii');
  v1.writeUInt32LE(1, 4);
  assert.strictEqual(format.classifyArchive(v1), format.ArchiveKind.EASR_V1);

  const v2 = finalizeGolden().superblock;
  assert.strictEqual(format.classifyArchive(v2), format.ArchiveKind.EASR_V2);

  const unknown = Buffer.alloc(8);
  unknown.write('EASR', 0, 'ascii');
  unknown.writeUInt32LE(99, 4);
  expectCode(() => format.classifyArchive(unknown),
    'ERR_EASR_UNSUPPORTED_VERSION');
  expectCode(() => format.classifyArchive(Buffer.from('EASR')),
    'ERR_EASR_TRUNCATED');
});

test('rejects every truncated signed-superblock prefix as v2 data', () => {
  const { superblock } = finalizeGolden();
  for (let length = 8; length < superblock.length; length++) {
    expectCode(() => format.parseSuperblock(superblock.subarray(0, length)),
      'ERR_EASR_TRUNCATED');
  }
  expectCode(() => format.parseSuperblock(Buffer.concat([
    superblock,
    Buffer.from([0])
  ])), 'ERR_EASR_SUPERBLOCK_SIZE');
});

test('verifies the fixed superblock before streaming authenticated index bytes', () => {
  const archive = finalizeGolden();
  const publicKey = crypto.createPublicKey(makePrivateKey());
  const options = {
    archiveSize: archive.archiveSize,
    resolveSigningKey: () => publicKey
  };
  const badSignature = Buffer.from(archive.superblock);
  badSignature[format.constants.SIGNATURE_OFFSET] ^= 1;
  const badIndex = Buffer.from(archive.index);
  badIndex[0] ^= 1;
  expectCode(() => format.verifyEnvelope(badSignature, badIndex, options),
    'ERR_EASR_SIGNATURE');

  const header = format.verifySuperblock(archive.superblock, options);
  assert.strictEqual(header.indexSize, archive.index.length);
  const stream = format.createIndexStreamVerifier(header);
  for (let offset = 0; offset < archive.index.length; offset += 7) {
    stream.update(archive.index.subarray(
      offset,
      Math.min(offset + 7, archive.index.length)
    ));
  }
  assert.strictEqual(stream.receivedSize, header.indexSize);
  assert.strictEqual(stream.finalize(), true);
  expectCode(() => format.createIndexStreamVerifier(
    format.parseSuperblock(archive.superblock)
  ), 'ERR_EASR_UNTRUSTED_HEADER');
});

test('rejects lossy surrogate strings and Windows path aliases', () => {
  for (const path of ['\ud800', '\udc00', 'a/\ud800']) {
    expectCode(() => createPlan([{ path, type: 'directory' }]),
      'ERR_EASR_INVALID_UTF8');
  }
  createPlan([{ path: '\ud83d\ude00', type: 'directory' }]);

  const windowsAliases = [
    'CON',
    'dir/NUL.txt',
    'COM¹',
    'dir/lpt².txt',
    'LPT³',
    'dir/file:stream',
    'C:/drive',
    '\\\\server\\share',
    'dir/trailing.',
    'dir/trailing '
  ];
  for (const path of windowsAliases) {
    expectCode(() => createPlan([{ path, type: 'directory' }]),
      'ERR_EASR_NON_CANONICAL_PATH');
  }
  for (const character of '<>"|?*') {
    expectCode(() => createPlan([{
      path: 'a' + character + 'b',
      type: 'directory'
    }]), 'ERR_EASR_NON_CANONICAL_PATH');
  }
  for (let codePoint = 1; codePoint <= 0x1f; codePoint++) {
    expectCode(() => createPlan([{
      path: 'a' + String.fromCharCode(codePoint) + 'b',
      type: 'directory'
    }]), 'ERR_EASR_NON_CANONICAL_PATH');
  }

  const emptyDigest = crypto.createHash('sha256').update('').digest();
  expectCode(() => createPlan([
    { path: 'app', type: 'directory' },
    {
      path: 'app/Foo.node',
      type: 'file',
      unpacked: true,
      size: 0,
      digest: emptyDigest
    },
    {
      path: 'app/foo.node',
      type: 'file',
      unpacked: true,
      size: 0,
      digest: emptyDigest
    }
  ]), 'ERR_EASR_PATH_COLLISION');

  const caseCollision = rawIndex(Buffer.concat([
    format.encodeUVarint(2),
    format.encodeUVarint(0),
    directoryRecord(0, 'A'),
    directoryRecord(0, 'a')
  ]));
  expectCode(() => format.decodeIndex(caseCollision, {
    expectedPayloadSize: 0
  }), 'ERR_EASR_PATH_COLLISION');
});

test('rejects dangling, cyclic, and over-depth symlink graphs', () => {
  expectCode(() => createPlan([
    { path: 'a', type: 'symlink', target: 'missing' }
  ]), 'ERR_EASR_SYMLINK_TARGET');
  expectCode(() => createPlan([
    { path: 'a', type: 'symlink', target: 'b' },
    { path: 'b', type: 'symlink', target: 'a' }
  ]), 'ERR_EASR_SYMLINK_CYCLE');

  const entries = [{ path: 'target', type: 'file', size: 0, chunks: [] }];
  for (let index = 0; index <= 40; index++) {
    entries.push({
      path: 'link' + String(index).padStart(2, '0'),
      type: 'symlink',
      target: index === 40
        ? 'target'
        : 'link' + String(index + 1).padStart(2, '0')
    });
  }
  expectCode(() => createPlan(entries), 'ERR_EASR_SYMLINK_DEPTH');
});

test('enforces compact-index count and byte budgets before allocation', () => {
  const excessiveChunkCount = rawIndex(Buffer.concat([
    format.encodeUVarint(0),
    format.encodeUVarint(format.constants.MAX_CHUNK_COUNT + 1)
  ]));
  expectCode(() => format.decodeIndex(excessiveChunkCount, {
    expectedPayloadSize: 0
  }), 'ERR_EASR_CHUNK_LIMIT');

  const { superblock } = finalizeGolden();
  const excessiveIndex = Buffer.from(superblock);
  excessiveIndex.writeUInt32LE(
    format.constants.MAX_INDEX_SIZE + 1,
    16
  );
  expectCode(() => format.parseSuperblock(excessiveIndex),
    'ERR_EASR_INDEX_LIMIT');
  assert(format.constants.MAX_INDEX_SIZE <= 16 * 1024 * 1024);
  assert(format.constants.MAX_CHUNK_COUNT * 16 <= 4 * 1024 * 1024);
});

test('prevents archive identity overrides during key derivation and finalize', () => {
  const plan = createGoldenPlan();
  expectCode(() => format.finalizeArchive(plan, {
    ...finalizationOptions(goldenTags()),
    archiveId: bytes(64, 32)
  }), 'ERR_EASR_ARCHIVE_PLAN');

  const changedEntries = goldenEntries();
  changedEntries[3].chunks[0].digest = Buffer.from(
    changedEntries[3].chunks[0].digest
  );
  changedEntries[3].chunks[0].digest[0] ^= 1;
  const changedPlan = createPlan(changedEntries);
  const masterKey = bytes(32, 32);
  assert(!format.deriveDataKey(masterKey, changedPlan).equals(
    format.deriveDataKey(masterKey, plan)
  ));
});

test('authenticates real AES-GCM data against wrong keys and tampering', () => {
  const plaintext = Buffer.from('authenticated EASR v2 payload');
  const plan = createPlan([{
    path: 'payload.bin',
    type: 'file',
    size: plaintext.length,
    chunks: [{
      codec: 'raw',
      storedSize: plaintext.length,
      digest: crypto.createHash('sha256').update(plaintext).digest()
    }]
  }]);
  const masterKey = bytes(32, 32);
  const key = format.deriveDataKey(masterKey, plan);
  const nonce = format.deriveChunkNonce(0);
  const aad = format.buildChunkAad(plan, plan.chunks[0]);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const archive = format.finalizeArchive(
    plan,
    finalizationOptions([tag])
  );
  const verified = format.verifyEnvelope(
    archive.superblock,
    archive.index,
    {
      archiveSize: archive.archiveSize,
      resolveSigningKey: () => crypto.createPublicKey(makePrivateKey())
    }
  );
  const runtimeKey = format.deriveDataKey(masterKey, verified.header);
  const runtimeAad = format.buildChunkAad(
    verified.header,
    verified.index.chunks[0]
  );
  const decrypt = (candidateKey, candidateCiphertext, candidateTag) => {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      candidateKey,
      nonce
    );
    decipher.setAAD(runtimeAad);
    decipher.setAuthTag(candidateTag);
    return Buffer.concat([
      decipher.update(candidateCiphertext),
      decipher.final()
    ]);
  };
  assert(decrypt(runtimeKey, ciphertext, tag).equals(plaintext));

  const wrongKey = Buffer.from(runtimeKey);
  wrongKey[0] ^= 1;
  assert.throws(() => decrypt(wrongKey, ciphertext, tag));
  const changedCiphertext = Buffer.from(ciphertext);
  changedCiphertext[0] ^= 1;
  assert.throws(() => decrypt(runtimeKey, changedCiphertext, tag));
  const changedTag = Buffer.from(tag);
  changedTag[0] ^= 1;
  assert.throws(() => decrypt(runtimeKey, ciphertext, changedTag));
});

test('keeps representative eager-index work inside startup budget', () => {
  const count = 10000;
  const digest = crypto.createHash('sha256').update('x').digest();
  const entries = [{ path: 'app', type: 'directory' }];
  for (let index = 0; index < count; index++) {
    entries.push({
      path: 'app/f' + String(index).padStart(5, '0'),
      type: 'file',
      size: 1,
      chunks: [{ codec: 'raw', storedSize: 1, digest }]
    });
  }
  const started = process.hrtime.bigint();
  const plan = createPlan(entries);
  const archive = format.finalizeArchive(
    plan,
    finalizationOptions(Array.from(
      { length: count },
      () => Buffer.alloc(16, 1)
    ))
  );
  const packedMs = Number(process.hrtime.bigint() - started) / 1e6;
  const verifyStarted = process.hrtime.bigint();
  const verified = format.verifyEnvelope(
    archive.superblock,
    archive.index,
    {
      archiveSize: archive.archiveSize,
      resolveSigningKey: () => crypto.createPublicKey(makePrivateKey())
    }
  );
  const verifiedMs = Number(process.hrtime.bigint() - verifyStarted) / 1e6;
  assert.strictEqual(verified.index.entryCount, count + 1);
  assert(archive.index.length <= count * 24 + 128);
  assert(packedMs < 5000, 'planning/finalize budget exceeded: ' + packedMs);
  assert(verifiedMs < 3000, 'startup verify budget exceeded: ' + verifiedMs);
});

test('derives canonical key ids and accepts only the matching public key', () => {
  const masterKey = bytes(32, 32);
  const privateKey = makePrivateKey();
  const publicKey = crypto.createPublicKey(privateKey);
  const dataKeyId = format.deriveDataKeyId(masterKey);
  const signingKeyId = format.deriveSigningKeyId(publicKey);
  assert.strictEqual(dataKeyId.length, format.constants.KEY_ID_SIZE);
  assert.strictEqual(signingKeyId.length, format.constants.KEY_ID_SIZE);
  assert(dataKeyId.equals(format.deriveDataKeyId(masterKey)));
  assert(signingKeyId.equals(format.deriveSigningKeyId(privateKey)));

  const plan = format.createArchivePlan({
    entries: [{ path: 'empty', type: 'file', size: 0, chunks: [] }],
    blockSizeLog2: 16,
    dataKeyId,
    epoch: BigInt(7)
  });
  const archive = format.finalizeArchive(plan, {
    tags: [],
    signingKeyId,
    privateKey
  });
  const resolverIds = [];
  format.verifyEnvelope(archive.superblock, archive.index, {
    archiveSize: archive.archiveSize,
    minimumEpoch: BigInt(7),
    resolveSigningKey: keyId => {
      resolverIds.push(keyId);
      return publicKey;
    }
  });
  assert.strictEqual(resolverIds.length, 1);
  assert(resolverIds[0].equals(signingKeyId));
  expectCode(() => format.verifyEnvelope(
    archive.superblock,
    archive.index,
    {
      archiveSize: archive.archiveSize,
      resolveSigningKey: () => privateKey
    }
  ), 'ERR_EASR_SIGNING_KEY');
  expectCode(() => format.verifyEnvelope(
    archive.superblock,
    archive.index,
    {
      archiveSize: archive.archiveSize,
      resolveSigningKey: () => publicKey.export({
        format: 'pem',
        type: 'spki'
      })
    }
  ), 'ERR_EASR_SIGNING_KEY');
  expectCode(() => format.finalizeArchive(plan, {
    tags: [],
    signingKeyId: Buffer.alloc(format.constants.KEY_ID_SIZE, 0x55),
    privateKey
  }), 'ERR_EASR_KEY_ID');

  const wrongMasterKey = Buffer.from(masterKey);
  wrongMasterKey[0] ^= 1;
  expectCode(() => format.deriveDataKey(wrongMasterKey, plan),
    'ERR_EASR_KEY_ID');
});

let failures = 0;
for (const { name, body } of tests) {
  try {
    body();
    console.log('ok - ' + name);
  } catch (error) {
    failures++;
    console.error('not ok - ' + name);
    console.error(error && error.stack ? error.stack : error);
  }
}

if (failures > 0) {
  console.error(failures + ' of ' + tests.length + ' tests failed');
  process.exitCode = 1;
} else {
  console.log(tests.length + ' tests passed');
}

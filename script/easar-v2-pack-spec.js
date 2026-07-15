#!/usr/bin/env node

/* global BigInt */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

const format = require('./lib/easar-v2-format');
const packer = require('./lib/easar-v2-packer');

const tests = [];
const test = (name, body) => tests.push({ name, body });

class SkipTest extends Error {}

const skip = reason => {
  throw new SkipTest(reason);
};

// Frozen from the removed legacy-v1 implementation. Keep this immutable so
// the v2 size gate cannot silently move with the current packer.
const FROZEN_V1_ARCHIVE_BYTES = 7744;

const expectCode = (body, code) => {
  assert.throws(body, error => {
    assert.strictEqual(error && error.code, code);
    return true;
  });
};

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

const keyMaterial = () => {
  const dataKey = bytes(32, 32);
  const signingPrivateKey = makePrivateKey();
  return {
    dataKey,
    dataKeyId: format.deriveDataKeyId(dataKey),
    signingPrivateKey,
    signingKeyId: format.deriveSigningKeyId(signingPrivateKey),
    epoch: BigInt(7)
  };
};

const withWorkspace = body => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'easar-v2-pack-spec-'));
  try {
    return body(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
};

const makeCorpus = root => {
  const source = path.join(root, 'source');
  fs.mkdirSync(path.join(source, 'sub'), { recursive: true });
  for (let index = 0; index < 24; index++) {
    fs.writeFileSync(
      path.join(source, 'sub', 'file-' + String(index).padStart(2, '0') + '.txt'),
      Buffer.from(('record-' + index + '\n').repeat(700))
    );
  }
  fs.writeFileSync(path.join(source, 'large.txt'), Buffer.alloc(150000, 0x61));
  fs.writeFileSync(path.join(source, 'binary.bin'), bytes(0, 256).subarray(0));
  fs.writeFileSync(path.join(source, 'empty'), Buffer.alloc(0));
  return source;
};

const packOptions = (source, output, overrides = {}) => ({
  source,
  output,
  trustWindowsOutputAcl: process.platform === 'win32',
  ...keyMaterial(),
  ...overrides
});

const verifyArchive = (archivePath, dataKey, publicKey) => {
  const fd = fs.openSync(archivePath, 'r');
  try {
    const superblock = Buffer.alloc(format.constants.SUPERBLOCK_SIZE);
    assert.strictEqual(fs.readSync(fd, superblock, 0, superblock.length, 0),
      superblock.length);
    const parsed = format.parseSuperblock(superblock);
    const index = Buffer.alloc(parsed.indexSize);
    assert.strictEqual(fs.readSync(
      fd,
      index,
      0,
      index.length,
      superblock.length
    ), index.length);
    const stat = fs.fstatSync(fd);
    const verified = format.verifyEnvelope(superblock, index, {
      archiveSize: stat.size,
      minimumEpoch: BigInt(7),
      resolveSigningKey: () => publicKey
    });
    const runtimeKey = format.deriveDataKey(dataKey, verified.header);
    return { fd, close: false, verified, runtimeKey };
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
};

const readPackedFile = (archivePath, relativePath, dataKey, publicKey) => {
  const opened = verifyArchive(archivePath, dataKey, publicKey);
  const { fd, verified, runtimeKey } = opened;
  try {
    const entry = verified.index.entries.find(item =>
      item.path === relativePath);
    assert(entry && entry.type === 'file' && !entry.unpacked);
    const parts = [];
    for (let offset = 0; offset < entry.chunkCount; offset++) {
      const chunk = verified.index.chunks[entry.firstChunk + offset];
      const ciphertext = Buffer.alloc(chunk.storedSize);
      assert.strictEqual(fs.readSync(
        fd,
        ciphertext,
        0,
        ciphertext.length,
        verified.payloadOffset + chunk.payloadOffset
      ), ciphertext.length);
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        runtimeKey,
        format.deriveChunkNonce(chunk.ordinal)
      );
      decipher.setAAD(format.buildChunkAad(verified.header, chunk));
      decipher.setAuthTag(chunk.tag);
      const stored = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
      ]);
      parts.push(chunk.codecName === 'deflate-raw'
        ? zlib.inflateRawSync(stored)
        : stored);
    }
    return Buffer.concat(parts);
  } finally {
    fs.closeSync(fd);
  }
};

test('requires key files and never accepts secret key command-line values', () => {
  expectCode(() => packer.parseCliArguments([
    '--src', 'source',
    '--out', 'app.asar'
  ]), 'ERR_EASR_KEY_REQUIRED');
  expectCode(() => packer.parseCliArguments([
    '--src', 'source',
    '--out', 'app.asar',
    '--data-key-hex', '00'
  ]), 'ERR_EASR_CLI_ARGUMENT');

  withWorkspace(root => {
    const badKey = path.join(root, 'bad.key');
    fs.writeFileSync(badKey, 'not a key', { mode: 0o600 });
    expectCode(() => packer.loadDataKey(badKey),
      process.platform === 'win32'
        ? 'ERR_EASR_KEY_ACL_UNVERIFIABLE'
        : 'ERR_EASR_DATA_KEY');
    expectCode(() => packer.loadDataKey(path.join(root, 'missing.key')),
      'ERR_EASR_KEY_FILE');

    const source = makeCorpus(root);
    const dataKeyFile = path.join(root, 'data.key');
    const signingKeyFile = path.join(root, 'signing.pem');
    const output = path.join(root, 'cli.asar');
    const keys = keyMaterial();
    fs.writeFileSync(dataKeyFile, keys.dataKey, { mode: 0o600 });
    fs.writeFileSync(signingKeyFile, keys.signingPrivateKey.export({
      format: 'pem',
      type: 'pkcs8'
    }), { mode: 0o600 });

    const guardedInput = Buffer.alloc(1024);
    const originalBufferFrom = Buffer.from;
    Buffer.from = (value, ...arguments_) => {
      if (value === guardedInput) {
        throw new Error('oversized stdin was copied');
      }
      return originalBufferFrom(value, ...arguments_);
    };
    try {
      expectCode(() => packer.runCli([
        '--src', source,
        '--out', path.join(root, 'oversized-stdin.asar'),
        '--data-key-file', '-',
        '--signing-key-file', signingKeyFile,
        '--epoch', '7'
      ], { stdinBuffer: guardedInput }), 'ERR_EASR_KEY_FILE_LIMIT');
    } finally {
      Buffer.from = originalBufferFrom;
      guardedInput.fill(0);
    }
    expectCode(() => packer.runCli([
      '--src', source,
      '--out', path.join(root, 'typed-stdin.asar'),
      '--data-key-file', '-',
      '--signing-key-file', signingKeyFile,
      '--epoch', '7'
    ], { stdinBuffer: new Uint8Array(32) }), 'ERR_EASR_KEY_FILE');

    const baseArguments = [
      '--src', source,
      '--signing-key-file', signingKeyFile,
      '--epoch', keys.epoch.toString()
    ];
    if (process.platform === 'win32') {
      expectCode(() => packer.runCli([
        ...baseArguments,
        '--out', output,
        '--data-key-file', dataKeyFile
      ]), 'ERR_EASR_KEY_ACL_UNVERIFIABLE');
    } else {
      const leakedKey = path.join(source, 'hardlinked-signing-key.pem');
      fs.linkSync(signingKeyFile, leakedKey);
      expectCode(() => packer.runCli([
        ...baseArguments,
        '--out', path.join(root, 'leaked-key.asar'),
        '--data-key-file', dataKeyFile
      ]), 'ERR_EASR_KEY_IN_SOURCE');
      fs.unlinkSync(leakedKey);

      const stats = packer.runCli([
        ...baseArguments,
        '--out', output,
        '--data-key-file', dataKeyFile
      ]);
      assert.strictEqual(stats.archiveBytes, fs.statSync(output).size);

      const stdinOutput = path.join(root, 'stdin.asar');
      const stdinStats = packer.runCli([
        ...baseArguments,
        '--out', stdinOutput,
        '--data-key-file', '-'
      ], { stdinBuffer: keys.dataKey });
      assert.strictEqual(stdinStats.archiveBytes,
        fs.statSync(stdinOutput).size);
    }
  });
});

test('packs deterministic bytes and decrypts every payload block', () => {
  withWorkspace(root => {
    const source = makeCorpus(root);
    const first = path.join(root, 'first.asar');
    const second = path.join(root, 'second.asar');
    const options = packOptions(source, first);
    const firstStats = packer.packArchive(options);
    const secondStats = packer.packArchive({
      ...options,
      output: second
    });
    assert(fs.readFileSync(first).equals(fs.readFileSync(second)));
    assert.strictEqual(firstStats.archiveBytes, secondStats.archiveBytes);
    assert(firstStats.compressedChunks > 0);
    assert(firstStats.estimatedJsChunkBufferCeilingBytes <= 3 * 64 * 1024);
    assert.strictEqual(firstStats.rssBytes, undefined);

    const publicKey = crypto.createPublicKey(options.signingPrivateKey);
    const expected = fs.readFileSync(path.join(source, 'large.txt'));
    assert(readPackedFile(
      first,
      'large.txt',
      options.dataKey,
      publicKey
    ).equals(expected));
    expectCode(() => verifyArchive(
      first,
      options.dataKey,
      crypto.createPublicKey(crypto.generateKeyPairSync('ed25519').privateKey)
    ), 'ERR_EASR_KEY_ID');

    const wrongKey = Buffer.from(options.dataKey);
    wrongKey[0] ^= 1;
    assert.throws(() => readPackedFile(
      first,
      'large.txt',
      wrongKey,
      publicKey
    ));
  });
});

test('rejects source mutation and removes every temporary output', () => {
  withWorkspace(root => {
    const source = makeCorpus(root);
    const output = path.join(root, 'mutated.asar');
    expectCode(() => packer.packArchive(packOptions(source, output, {
      hooks: {
        beforeSourceRevalidate: () => {
          fs.appendFileSync(path.join(source, 'large.txt'), 'changed');
        }
      }
    })), 'ERR_EASR_SOURCE_CHANGED');
    assert(!fs.existsSync(output));
    assert.deepStrictEqual(
      fs.readdirSync(root).filter(name => name.startsWith('.easar-v2-')),
      []
    );
  });
});

test('rejects staged spool mutation before encryption', () => {
  withWorkspace(root => {
    const source = makeCorpus(root);
    const output = path.join(root, 'mutated-spool.asar');
    expectCode(() => packer.packArchive(packOptions(source, output, {
      hooks: {
        beforeEncrypt: ({ spoolPath }) => {
          const fd = fs.openSync(spoolPath, 'r+');
          try {
            const byte = Buffer.alloc(1);
            assert.strictEqual(fs.readSync(fd, byte, 0, 1, 0), 1);
            byte[0] ^= 1;
            assert.strictEqual(fs.writeSync(fd, byte, 0, 1, 0), 1);
          } finally {
            fs.closeSync(fd);
          }
        }
      }
    })), 'ERR_EASR_SPOOL_CHANGED');
    assert(!fs.existsSync(output));
    assert.deepStrictEqual(
      fs.readdirSync(root).filter(name => name.startsWith('.easar-v2-')),
      []
    );
  });
});

test('rejects finalized archive mutation after the commit hook', () => {
  withWorkspace(root => {
    const source = makeCorpus(root);
    const output = path.join(root, 'mutated-final.asar');
    expectCode(() => packer.packArchive(packOptions(source, output, {
      hooks: {
        beforeCommit: ({ temporaryArchive }) => {
          fs.writeFileSync(temporaryArchive, 'not an EASR archive');
        }
      }
    })), 'ERR_EASR_ARCHIVE_CHANGED');
    assert(!fs.existsSync(output));
    assert.deepStrictEqual(
      fs.readdirSync(root).filter(name => name.startsWith('.easar-v2-')),
      []
    );
  });
});

test('revalidates inherited and non-enumerable mutation hooks', () => {
  withWorkspace(root => {
    const source = makeCorpus(root);
    for (const kind of ['inherited', 'non-enumerable']) {
      const output = path.join(root, kind + '-hook.asar');
      const beforeCommit = ({ temporaryArchive }) => {
        fs.writeFileSync(temporaryArchive, 'not an EASR archive');
      };
      let hooks;
      if (kind === 'inherited') {
        hooks = Object.create({ beforeCommit });
      } else {
        hooks = {};
        Object.defineProperty(hooks, 'beforeCommit', { value: beforeCommit });
      }
      expectCode(() => packer.packArchive(packOptions(source, output, {
        hooks
      })), 'ERR_EASR_ARCHIVE_CHANGED');
      assert(!fs.existsSync(output));
    }
    assert.deepStrictEqual(
      fs.readdirSync(root).filter(name => name.startsWith('.easar-v2-')),
      []
    );
  });
});

test('rejects public sidecar mutation after the publication hook', () => {
  withWorkspace(root => {
    const source = makeCorpus(root);
    const output = path.join(root, 'mutated-sidecar.asar');
    let primaryError;
    try {
      packer.packArchive(packOptions(source, output, {
        unpack: new Set(['binary.bin']),
        hooks: {
          afterSidecarPublish: ({ sidecar }) => {
            fs.writeFileSync(path.join(sidecar, 'binary.bin'), 'tampered');
          }
        }
      }));
    } catch (error) {
      primaryError = error;
    }
    assert(primaryError);
    assert.strictEqual(primaryError.code, 'ERR_EASR_UNPACKED_CHANGED');
    assert.strictEqual(primaryError.cleanup.status, 'residual');
    assert(primaryError.cleanup.residualPaths.includes(output + '.unpacked'));
    assert(!fs.existsSync(output));
  });
});

test('never recursively removes a replaced public sidecar during rollback', () => {
  withWorkspace(root => {
    const source = makeCorpus(root);
    const output = path.join(root, 'sidecar-race.asar');
    let primaryError;
    try {
      packer.packArchive(packOptions(source, output, {
        unpack: new Set(['binary.bin']),
        hooks: {
          afterSidecarPublish: ({ sidecar }) => {
            fs.renameSync(sidecar, sidecar + '.original');
            fs.mkdirSync(sidecar);
            fs.writeFileSync(path.join(sidecar, 'sentinel'), 'do not delete');
            throw new Error('injected post-sidecar failure');
          }
        }
      }));
    } catch (error) {
      primaryError = error;
    }
    assert(primaryError);
    assert.strictEqual(primaryError.cleanup.status, 'residual');
    assert(primaryError.cleanup.residualPaths.includes(output + '.unpacked'));
    assert.strictEqual(fs.readFileSync(
      path.join(output + '.unpacked', 'sentinel'), 'utf8'), 'do not delete');
    assert(!fs.existsSync(output));
  });
});

test('preserves an atomic destination on failures and rejects source outputs', () => {
  withWorkspace(root => {
    const source = makeCorpus(root);
    const existing = path.join(root, 'existing.asar');
    fs.writeFileSync(existing, 'sentinel');
    expectCode(() => packer.packArchive(packOptions(source, existing)),
      'ERR_EASR_OUTPUT_EXISTS');
    assert.strictEqual(fs.readFileSync(existing, 'utf8'), 'sentinel');

    const failed = path.join(root, 'failed.asar');
    assert.throws(() => packer.packArchive(packOptions(source, failed, {
      hooks: {
        beforeCommit: () => {
          throw new Error('injected commit failure');
        }
      }
    })), /injected commit failure/);
    assert(!fs.existsSync(failed));

    expectCode(() => packer.packArchive(packOptions(
      source,
      path.join(source, 'inside.asar')
    )), 'ERR_EASR_OUTPUT_IN_SOURCE');
  });
});

test('publishes with create-if-absent semantics under a commit race', () => {
  withWorkspace(root => {
    const source = makeCorpus(root);
    const output = path.join(root, 'raced.asar');
    expectCode(() => packer.packArchive(packOptions(source, output, {
      hooks: {
        beforeCommit: () => fs.writeFileSync(output, 'concurrent sentinel')
      }
    })), 'ERR_EASR_OUTPUT_EXISTS');
    assert.strictEqual(fs.readFileSync(output, 'utf8'),
      'concurrent sentinel');
    assert(!fs.existsSync(output + '.unpacked'));
  });
});

test('revalidates staged unpacked bytes after the final commit hook', () => {
  withWorkspace(root => {
    const source = makeCorpus(root);
    const output = path.join(root, 'tampered.asar');
    expectCode(() => packer.packArchive(packOptions(source, output, {
      unpack: new Set(['binary.bin']),
      hooks: {
        beforeCommit: ({ stagedUnpackRoot }) => {
          fs.appendFileSync(
            path.join(stagedUnpackRoot, 'binary.bin'),
            'tampered'
          );
        }
      }
    })), 'ERR_EASR_UNPACKED_CHANGED');
    assert(!fs.existsSync(output));
    assert(!fs.existsSync(output + '.unpacked'));
  });
});

test('bounds secret and unpack-list inputs and rejects unsafe keys', () => {
  withWorkspace(root => {
    const zeroKey = path.join(root, 'zero.key');
    const oversizedKey = path.join(root, 'oversized.key');
    const oversizedSigningKey = path.join(root, 'oversized-signing.key');
    fs.writeFileSync(zeroKey, Buffer.alloc(32), { mode: 0o600 });
    fs.writeFileSync(oversizedKey, Buffer.alloc(64 * 1024), { mode: 0o600 });
    fs.writeFileSync(oversizedSigningKey, Buffer.alloc(32 * 1024), {
      mode: 0o600
    });
    expectCode(() => packer.loadDataKey('-', {
      stdinBuffer: Buffer.alloc(32)
    }), 'ERR_EASR_DATA_KEY');
    expectCode(() => packer.loadDataKey(oversizedKey),
      'ERR_EASR_KEY_FILE_LIMIT');
    expectCode(() => packer.loadSigningPrivateKey(oversizedSigningKey),
      'ERR_EASR_KEY_FILE_LIMIT');
    expectCode(() => packer.loadDataKey('-', {
      stdinBuffer: Buffer.alloc(1024)
    }), 'ERR_EASR_KEY_FILE_LIMIT');

    if (process.platform !== 'win32') {
      const publicKeyFile = path.join(root, 'public.key');
      fs.writeFileSync(publicKeyFile, bytes(32, 32), { mode: 0o644 });
      fs.chmodSync(publicKeyFile, 0o644);
      expectCode(() => packer.loadDataKey(publicKeyFile),
        'ERR_EASR_KEY_PERMISSIONS');
      const linkedKeyFile = path.join(root, 'linked.key');
      fs.symlinkSync(zeroKey, linkedKeyFile, 'file');
      expectCode(() => packer.loadDataKey(linkedKeyFile),
        'ERR_EASR_KEY_FILE');
    }

    const source = makeCorpus(root);
    const keys = keyMaterial();
    expectCode(() => packer.packArchive(packOptions(
      source,
      path.join(root, 'zero.asar'),
      { dataKey: Buffer.alloc(32), dataKeyId: undefined }
    )), 'ERR_EASR_DATA_KEY');
    const wrongDataKeyId = Buffer.from(keys.dataKeyId);
    wrongDataKeyId[0] ^= 1;
    expectCode(() => packer.packArchive(packOptions(
      source,
      path.join(root, 'wrong-id.asar'),
      { dataKeyId: wrongDataKeyId }
    )), 'ERR_EASR_KEY_ID');
    const dataKeyFile = path.join(root, 'data.key');
    const signingKeyFile = path.join(root, 'signing.pem');
    const unpackList = path.join(root, 'unpack-list.txt');
    fs.writeFileSync(dataKeyFile, keys.dataKey, { mode: 0o600 });
    fs.writeFileSync(signingKeyFile, keys.signingPrivateKey.export({
      format: 'pem',
      type: 'pkcs8'
    }), { mode: 0o600 });
    fs.writeFileSync(unpackList, Buffer.alloc(1024 * 1024 + 1, 0x61));
    expectCode(() => packer.runCli([
      '--src', source,
      '--out', path.join(root, 'bounded.asar'),
      '--data-key-file', dataKeyFile,
      '--signing-key-file', signingKeyFile,
      '--epoch', '7',
      '--unpack-list', unpackList
    ]), 'ERR_EASR_UNPACK_LIST_LIMIT');
  });
});

test('preflights fail-closed platform capabilities without unsafe fallback', () => {
  const contract = packer.getPlatformContract();
  assert.strictEqual(contract.unsafePublicationFallback, false);
  assert.strictEqual(contract.publicationRequirement,
    'same-volume-hard-link-create-if-absent');
  if (process.platform === 'win32') {
    assert.strictEqual(contract.keyFileAclVerification,
      'unavailable-fail-closed');
  } else {
    assert.strictEqual(contract.keyFileAclVerification,
      'posix-mode-mask-enforced');
  }

  withWorkspace(root => {
    const supported = packer.preflightCapabilities(root, {
      force: true,
      trustWindowsOutputAcl: process.platform === 'win32'
    });
    assert.strictEqual(supported.atomicNoClobberPublication, true);
    const originalLinkSync = fs.linkSync;
    fs.linkSync = () => {
      const error = new Error('hard links unavailable');
      error.code = 'EPERM';
      throw error;
    };
    try {
      let capabilityError;
      try {
        packer.preflightCapabilities(root, {
          force: true,
          trustWindowsOutputAcl: process.platform === 'win32'
        });
      } catch (error) {
        capabilityError = error;
      }
      assert(capabilityError);
      assert.strictEqual(capabilityError.code,
        'ERR_EASR_CAPABILITY_HARDLINK');
      assert.strictEqual(capabilityError.capability,
        'same-volume-hard-link-create-if-absent');
      assert.strictEqual(
        capabilityError.platformContract.unsafePublicationFallback,
        false
      );
    } finally {
      fs.linkSync = originalLinkSync;
    }
  });
});

test('uses safe temporary and published file permissions', () => {
  if (process.platform === 'win32') {
    skip('Windows does not expose POSIX mode enforcement');
  }
  withWorkspace(root => {
    const source = path.join(root, 'source');
    fs.mkdirSync(source);
    fs.writeFileSync(path.join(source, 'normal.bin'), 'normal');
    fs.writeFileSync(path.join(source, 'executable.bin'), 'executable', {
      mode: 0o755
    });
    fs.chmodSync(path.join(source, 'executable.bin'), 0o755);
    const output = path.join(root, 'permissions.asar');
    const expectedArchiveMode = 0o644 & ~process.umask();
    const expectedNormalMode = 0o644 & ~process.umask();
    const expectedExecutableMode = 0o755 & ~process.umask();
    packer.packArchive(packOptions(source, output, {
      unpack: new Set(['normal.bin', 'executable.bin']),
      hooks: {
        beforeCommit: ({ temporaryArchive, stagedUnpackRoot }) => {
          assert.strictEqual(fs.statSync(temporaryArchive).mode & 0o777, 0o600);
          assert.strictEqual(fs.statSync(
            path.join(stagedUnpackRoot, 'normal.bin')
          ).mode & 0o777, 0o600);
        }
      }
    }));
    assert.strictEqual(fs.statSync(output).mode & 0o777,
      expectedArchiveMode);
    assert.strictEqual(fs.statSync(
      path.join(output + '.unpacked', 'normal.bin')
    ).mode & 0o777, expectedNormalMode);
    assert.strictEqual(fs.statSync(
      path.join(output + '.unpacked', 'executable.bin')
    ).mode & 0o777, expectedExecutableMode);
  });
});

test('reports, wipes, and preserves commit state for cleanup residuals', () => {
  withWorkspace(root => {
    const source = makeCorpus(root);
    const originalRmSync = fs.rmSync;
    fs.rmSync = (target, options) => {
      if (path.basename(target).startsWith('.easar-v2-')) {
        throw new Error('injected cleanup failure');
      }
      return originalRmSync(target, options);
    };
    try {
      let primaryError;
      try {
        packer.packArchive(packOptions(
          source,
          path.join(root, 'primary.asar'),
          {
            unpack: new Set(['binary.bin']),
            hooks: {
              beforeCommit: () => {
                throw new Error('primary failure');
              }
            }
          }
        ));
      } catch (error) {
        primaryError = error;
      }
      assert(primaryError);
      assert.strictEqual(primaryError.message, 'primary failure');
      assert.strictEqual(primaryError.cleanup.status, 'residual');
      assert.strictEqual(primaryError.cleanup.archiveCommitted, false);
      assert(path.isAbsolute(primaryError.cleanup.residualPaths[0]));
      assert.strictEqual(fs.statSync(path.join(
        primaryError.cleanup.residualPaths[0],
        'unpacked',
        'binary.bin'
      )).size, 0);

      const committed = path.join(root, 'committed.asar');
      const stats = packer.packArchive(packOptions(source, committed, {
        unpack: new Set(['binary.bin'])
      }));
      assert.strictEqual(stats.archiveBytes, fs.statSync(committed).size);
      assert.strictEqual(stats.cleanup.status, 'residual');
      assert.strictEqual(stats.cleanup.archiveCommitted, true);
      assert(path.isAbsolute(stats.cleanup.residualPaths[0]));
      assert.strictEqual(fs.statSync(path.join(
        stats.cleanup.residualPaths[0],
        'payload.spool'
      )).size, 0);
      assert(fs.readFileSync(path.join(
        committed + '.unpacked',
        'binary.bin'
      )).equals(fs.readFileSync(path.join(source, 'binary.bin'))));
      assert(!fs.existsSync(path.join(
        stats.cleanup.residualPaths[0],
        'unpacked',
        'binary.bin'
      )));
      expectCode(() => packer.requireCleanCliResult(stats),
        'ERR_EASR_CLEANUP_RESIDUAL');
    } finally {
      fs.rmSync = originalRmSync;
      for (const name of fs.readdirSync(root)) {
        if (name.startsWith('.easar-v2-')) {
          originalRmSync(path.join(root, name), {
            recursive: true,
            force: true
          });
        }
      }
    }
  });
});

test('reports a recovered cleanup failure without failing the archive', () => {
  withWorkspace(root => {
    const source = makeCorpus(root);
    const originalRmSync = fs.rmSync;
    let injected = false;
    fs.rmSync = (target, options) => {
      if (!injected && path.basename(target).startsWith('.easar-v2-')) {
        injected = true;
        throw new Error('one cleanup failure');
      }
      return originalRmSync(target, options);
    };
    try {
      const output = path.join(root, 'recovered.asar');
      const stats = packer.packArchive(packOptions(source, output));
      assert.strictEqual(stats.cleanup.status, 'recovered');
      assert.strictEqual(stats.cleanup.archiveCommitted, true);
      assert.deepStrictEqual(stats.cleanup.residualPaths, []);
      assert.strictEqual(packer.requireCleanCliResult(stats), stats);
    } finally {
      fs.rmSync = originalRmSync;
    }
  });
});

test('signs symlinks and unpacked file digests without payload duplication', () => {
  withWorkspace(root => {
    const source = path.join(root, 'source');
    fs.mkdirSync(source);
    fs.writeFileSync(path.join(source, 'target.js'), 'module.exports = 42;\n');
    fs.writeFileSync(path.join(source, 'native.node'), bytes(0, 128));
    try {
      fs.symlinkSync('target.js', path.join(source, 'link.js'), 'file');
    } catch (error) {
      if (process.platform === 'win32' && error.code === 'EPERM') {
        skip('Windows symbolic-link privilege is unavailable');
      }
      throw error;
    }
    const output = path.join(root, 'app.asar');
    const options = packOptions(source, output, {
      unpack: new Set(['native.node'])
    });
    const stats = packer.packArchive(options);
    assert.strictEqual(stats.unpackedFiles, 1);

    const opened = verifyArchive(
      output,
      options.dataKey,
      crypto.createPublicKey(options.signingPrivateKey)
    );
    try {
      const link = opened.verified.index.entries.find(
        entry => entry.path === 'link.js'
      );
      assert.strictEqual(link.type, 'symlink');
      assert.strictEqual(link.target, 'target.js');
      const unpacked = opened.verified.index.entries.find(
        entry => entry.path === 'native.node'
      );
      assert.strictEqual(unpacked.unpacked, true);
      const expected = fs.readFileSync(path.join(source, 'native.node'));
      assert(unpacked.digest.equals(
        crypto.createHash('sha256').update(expected).digest()
      ));
      assert(fs.readFileSync(
        path.join(output + '.unpacked', 'native.node')
      ).equals(expected));
    } finally {
      fs.closeSync(opened.fd);
    }
  });
});

test('keeps v2 within the v1 size budget and reports packing cost', () => {
  withWorkspace(root => {
    const source = makeCorpus(root);
    const v2 = path.join(root, 'v2.asar');
    const v2Stats = packer.packArchive(packOptions(source, v2));
    const v2Bytes = fs.statSync(v2).size;
    assert(v2Bytes <= FROZEN_V1_ARCHIVE_BYTES,
      'v2 ' + v2Bytes + ' exceeds frozen v1 ' +
        FROZEN_V1_ARCHIVE_BYTES);
    assert.strictEqual(v2Stats.archiveBytes, v2Bytes);
    assert(v2Stats.packMs < 5000);
    assert.strictEqual(
      v2Stats.archiveBytes,
      v2Stats.superblockBytes + v2Stats.indexBytes + v2Stats.payloadBytes
    );
  });
});

test('compresses later blocks of a text file after a random prefix', () => {
  withWorkspace(root => {
    const source = path.join(root, 'source');
    fs.mkdirSync(source);
    fs.writeFileSync(path.join(source, 'mixed.js'), Buffer.concat([
      crypto.randomBytes(64 * 1024),
      Buffer.alloc(64 * 1024, 0x61)
    ]));
    const adaptive = packer.packArchive(packOptions(
      source,
      path.join(root, 'adaptive.asar')
    ));
    const raw = packer.packArchive(packOptions(
      source,
      path.join(root, 'raw.asar'),
      { compression: false }
    ));
    assert.strictEqual(adaptive.compressionAttempts, 2);
    assert.strictEqual(adaptive.compressedChunks, 1);
    assert(adaptive.payloadBytes < raw.payloadBytes);
  });
});

test('probes only one block of a 32 MiB incompressible unknown file', () => {
  withWorkspace(root => {
    const source = path.join(root, 'source');
    fs.mkdirSync(source);
    const randomPath = path.join(source, 'random.bin');
    const fd = fs.openSync(randomPath, 'wx', 0o600);
    try {
      for (let offset = 0; offset < 32; offset++) {
        fs.writeSync(fd, crypto.randomBytes(1024 * 1024));
      }
    } finally {
      fs.closeSync(fd);
    }
    const adaptive = packer.packArchive(packOptions(
      source,
      path.join(root, 'adaptive.asar')
    ));
    const raw = packer.packArchive(packOptions(
      source,
      path.join(root, 'raw.asar'),
      { compression: false }
    ));
    assert(adaptive.compressionAttempts <= 1);
    assert.strictEqual(adaptive.compressedChunks, 0);
    assert.strictEqual(adaptive.payloadBytes, raw.payloadBytes);
    assert(adaptive.packMs <= raw.packMs * 1.35 + 100,
      'adaptive ' + adaptive.packMs + 'ms exceeds raw ' + raw.packMs + 'ms');
  });
});

let failures = 0;
let skipped = 0;
for (const { name, body } of tests) {
  try {
    body();
    console.log('ok - ' + name);
  } catch (error) {
    if (error instanceof SkipTest) {
      skipped++;
      console.log('skip - ' + name + ' (' + error.message + ')');
      continue;
    }
    failures++;
    console.error('not ok - ' + name);
    console.error(error && error.stack ? error.stack : error);
  }
}

if (failures > 0) {
  console.error(failures + ' of ' + tests.length + ' tests failed');
  process.exitCode = 1;
} else {
  console.log((tests.length - skipped) + ' tests passed, ' + skipped +
    ' skipped');
}

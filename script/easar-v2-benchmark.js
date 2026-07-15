#!/usr/bin/env node

/* global BigInt */

const assert = require('assert');
const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  isMainThread,
  parentPort,
  workerData,
  Worker
} = require('worker_threads');

const packer = require('./lib/easar-v2-packer');

const MIB = 1024 * 1024;
const RSS_SAMPLE_INTERVAL_MS = 2;
const RSS_CASES_MIB = [16, 32];

const bytes = (start, length) => Buffer.from(
  Array.from({ length }, (_, index) => (start + index) & 0xff)
);

const keyMaterial = () => ({
  dataKey: bytes(32, 32),
  signingPrivateKey: crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      bytes(0, 32)
    ]),
    format: 'der',
    type: 'pkcs8'
  })
});

const writeFully = (fd, buffer) => {
  let offset = 0;
  while (offset < buffer.length) {
    offset += fs.writeSync(fd, buffer, offset, buffer.length - offset);
  }
};

const makeRandomBinary = (filename, mebibytes) => {
  const fd = fs.openSync(filename, 'wx', 0o600);
  const randomBlock = crypto.randomBytes(MIB);
  try {
    for (let index = 0; index < mebibytes; index++) {
      writeFully(fd, randomBlock);
    }
    fs.fsyncSync(fd);
  } finally {
    randomBlock.fill(0);
    fs.closeSync(fd);
  }
};

const runRssWorker = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'easar-v2-rss-'));
  const source = path.join(root, 'source');
  fs.mkdirSync(source);
  makeRandomBinary(
    path.join(source, 'random.bin'),
    workerData.mebibytes
  );
  const keys = keyMaterial();
  parentPort.postMessage({ type: 'ready' });
  parentPort.once('message', message => {
    if (!message || message.type !== 'start') return;
    let response;
    try {
      const stats = packer.packArchive({
        source,
        output: path.join(root, 'random.asar'),
        trustWindowsOutputAcl: process.platform === 'win32',
        dataKey: keys.dataKey,
        signingPrivateKey: keys.signingPrivateKey,
        epoch: BigInt(7)
      });
      response = {
        type: 'result',
        stats: {
          archiveBytes: stats.archiveBytes,
          payloadBytes: stats.payloadBytes,
          packMs: stats.packMs,
          compressionAttempts: stats.compressionAttempts,
          compressedChunks: stats.compressedChunks,
          cleanupStatus: stats.cleanup.status
        }
      };
    } catch (error) {
      response = {
        type: 'error',
        code: error.code || null,
        message: error.message,
        stack: error.stack
      };
    } finally {
      keys.dataKey.fill(0);
      fs.rmSync(root, { recursive: true, force: true });
    }
    parentPort.postMessage(response);
    parentPort.close();
  });
};

const sampleRssInCurrentProcess = mebibytes => new Promise((resolve, reject) => {
  const worker = new Worker(__filename, {
    workerData: { mebibytes }
  });
  let baselineRss;
  let peakRss;
  let sampler;
  let settled = false;
  const stop = () => {
    if (sampler) clearInterval(sampler);
    sampler = null;
  };
  worker.on('message', message => {
    if (message.type === 'ready') {
      baselineRss = process.memoryUsage().rss;
      peakRss = baselineRss;
      sampler = setInterval(() => {
        peakRss = Math.max(peakRss, process.memoryUsage().rss);
      }, RSS_SAMPLE_INTERVAL_MS);
      worker.postMessage({ type: 'start' });
      return;
    }
    if (message.type === 'error') {
      stop();
      settled = true;
      const error = new Error(message.message);
      error.code = message.code;
      error.stack = message.stack;
      reject(error);
      return;
    }
    if (message.type === 'result') {
      peakRss = Math.max(peakRss, process.memoryUsage().rss);
      stop();
      settled = true;
      resolve({
        mebibytes,
        baselineRssBytes: baselineRss,
        peakRssBytes: peakRss,
        rssDeltaBytes: Math.max(0, peakRss - baselineRss),
        ...message.stats
      });
    }
  });
  worker.on('error', error => {
    stop();
    if (!settled) reject(error);
  });
  worker.on('exit', code => {
    stop();
    if (!settled && code !== 0) {
      reject(new Error('RSS benchmark worker exited with code ' + code));
    }
  });
});

const sampleIndependentRssCase = mebibytes => {
  const child = childProcess.spawnSync(process.execPath, [
    __filename,
    '--rss-child',
    String(mebibytes)
  ], {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
    timeout: 120000
  });
  if (child.error) throw child.error;
  if (child.status !== 0) {
    throw new Error(
      'independent RSS child failed: ' + (child.stderr || child.stdout)
    );
  }
  return JSON.parse(child.stdout);
};

const runFrozenCorpora = () => {
  const electronRoot = path.resolve(__dirname, '..');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'easar-v2-corpus-'));
  const keys = keyMaterial();
  const definitions = [
    {
      name: 'electron-lib',
      source: path.join(electronRoot, 'lib'),
      v1Bytes: 325616,
      baselineV2Bytes: 96156,
      maxV2RegressionBytes: 2048,
      maxPackMs: 2000
    },
    {
      name: 'fixture-apps',
      source: path.join(electronRoot, 'spec', 'fixtures', 'apps'),
      v1Bytes: 94442,
      baselineV2Bytes: 80055,
      maxV2RegressionBytes: 2048,
      maxPackMs: 1500
    }
  ];
  try {
    return definitions.map(definition => {
      const stats = packer.packArchive({
        source: definition.source,
        output: path.join(root, definition.name + '.asar'),
        trustWindowsOutputAcl: process.platform === 'win32',
        dataKey: keys.dataKey,
        signingPrivateKey: keys.signingPrivateKey,
        epoch: BigInt(7),
        compressionLevel: 9
      });
      assert.strictEqual(stats.cleanup.status, 'clean');
      assert(stats.archiveBytes <= definition.v1Bytes,
        definition.name + ' exceeds frozen v1 size');
      assert(stats.archiveBytes <= definition.baselineV2Bytes +
        definition.maxV2RegressionBytes,
      definition.name + ' exceeds frozen v2 regression budget');
      assert(stats.packMs <= definition.maxPackMs,
        definition.name + ' pack time exceeded ' + definition.maxPackMs +
        'ms: ' + stats.packMs);
      return {
        name: definition.name,
        v1Bytes: definition.v1Bytes,
        baselineV2Bytes: definition.baselineV2Bytes,
        maxV2RegressionBytes: definition.maxV2RegressionBytes,
        compressionLevel: 9,
        v2Bytes: stats.archiveBytes,
        deltaFromBaselineV2Bytes:
          stats.archiveBytes - definition.baselineV2Bytes,
        sizeRatio: stats.archiveBytes / definition.v1Bytes,
        packMs: stats.packMs,
        indexBytes: stats.indexBytes,
        payloadBytes: stats.payloadBytes
      };
    });
  } finally {
    keys.dataKey.fill(0);
    fs.rmSync(root, { recursive: true, force: true });
  }
};

const main = async () => {
  const slow = process.argv.includes('--slow');
  const frozenCorpora = runFrozenCorpora();
  const report = {
    benchmark: 'easar-v2-size-performance-rss',
    mode: slow ? 'slow' : 'frozen-corpora-only',
    frozenCorpora
  };
  if (slow) {
    const rssCases = [];
    for (const mebibytes of RSS_CASES_MIB) {
      rssCases.push(sampleIndependentRssCase(mebibytes));
    }
    for (const result of rssCases) {
      assert(result.compressionAttempts <= 1,
        result.mebibytes + ' MiB random.bin compressed too many probes');
      assert.strictEqual(result.compressedChunks, 0);
      assert.strictEqual(result.payloadBytes, result.mebibytes * MIB);
      assert.strictEqual(result.cleanupStatus, 'clean');
    }
    const peakRssGrowthBytes = rssCases[1].peakRssBytes -
      rssCases[0].peakRssBytes;
    const peakRssSlopeBytesPerInputByte = peakRssGrowthBytes /
      ((RSS_CASES_MIB[1] - RSS_CASES_MIB[0]) * MIB);
    assert(rssCases[1].rssDeltaBytes <= 96 * MIB,
      '32 MiB RSS delta exceeded 96 MiB');
    assert(rssCases[1].peakRssBytes <= 160 * MIB,
      '32 MiB process peak RSS exceeded 160 MiB');
    assert(peakRssGrowthBytes <= 32 * MIB,
      'peak RSS grew by more than 32 MiB when input grew by 16 MiB');
    report.rss = {
      sampleIntervalMs: RSS_SAMPLE_INTERVAL_MS,
      isolation: 'one sampler process and worker per input size',
      cases: rssCases,
      peakGrowthBytes16To32MiB: peakRssGrowthBytes,
      peakSlopeBytesPerInputByte: peakRssSlopeBytesPerInputByte,
      deltaGrowthBytes16To32MiB:
        rssCases[1].rssDeltaBytes - rssCases[0].rssDeltaBytes,
      gates: {
        max32MiBDeltaBytes: 96 * MIB,
        max32MiBPeakBytes: 160 * MIB,
        maxPeakGrowthBytes16To32MiB: 32 * MIB
      }
    };
  } else {
    report.rss = {
      skipped: true,
      run: 'node script/easar-v2-benchmark.js --slow'
    };
  }
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
};

const rssChildMain = async mebibytes => {
  const result = await sampleRssInCurrentProcess(mebibytes);
  process.stdout.write(JSON.stringify(result) + '\n');
};

if (isMainThread) {
  const childIndex = process.argv.indexOf('--rss-child');
  const operation = childIndex === -1
    ? main()
    : rssChildMain(Number(process.argv[childIndex + 1]));
  operation.catch(error => {
    process.stderr.write((error.stack || String(error)) + '\n');
    process.exitCode = 1;
  });
} else {
  runRssWorker();
}

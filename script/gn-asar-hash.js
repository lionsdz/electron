#!/usr/bin/env node

/* global BigInt */

const crypto = require('crypto');
const fs = require('fs');

const EASR_MAGIC = Buffer.from('EASR', 'ascii');

const readExact = (fd, buffer, position) => {
  let offset = 0;
  while (offset < buffer.length) {
    const count = fs.readSync(
      fd,
      buffer,
      offset,
      buffer.length - offset,
      position + offset
    );
    if (count <= 0) throw new Error('truncated ASAR metadata');
    offset += count;
  }
};

const hashEasrV2Header = archive => {
  // Ordinary builds never load the v2 codec, preserving their tiny historical
  // hash action. The codec is build-only and loaded solely after exact magic
  // and version classification.
  const format = require('./lib/easar-v2-format');
  const fd = fs.openSync(archive, 'r');
  try {
    const superblock = Buffer.alloc(format.constants.SUPERBLOCK_SIZE);
    readExact(fd, superblock, 0);
    const parsed = format.parseSuperblock(superblock);
    const stat = fs.fstatSync(fd);
    const expectedSize = BigInt(format.constants.SUPERBLOCK_SIZE) +
      BigInt(parsed.indexSize) + BigInt(parsed.payloadSize);
    if (BigInt(stat.size) !== expectedSize) {
      throw new Error('EASR v2 archive has truncation or trailing bytes');
    }
    const indexHasher = crypto.createHash('sha256');
    const block = Buffer.allocUnsafe(Math.min(parsed.indexSize, 64 * 1024));
    let remaining = parsed.indexSize;
    let position = superblock.length;
    while (remaining > 0) {
      const size = Math.min(remaining, block.length);
      const slice = block.subarray(0, size);
      readExact(fd, slice, position);
      indexHasher.update(slice);
      position += size;
      remaining -= size;
    }
    const indexHash = indexHasher.digest();
    if (!crypto.timingSafeEqual(indexHash, parsed.indexHash)) {
      throw new Error('EASR v2 signed index hash does not match');
    }
    // The fixed superblock is the EASR header. It transitively commits to the
    // complete index through indexHash, while the index commits to every GCM
    // tag. Hashing only these 200 bytes keeps macOS fuse validation O(1).
    return crypto.createHash('sha256').update(superblock).digest('hex');
  } finally {
    fs.closeSync(fd);
  }
};

const hashAsarHeader = archive => {
  const fd = fs.openSync(archive, 'r');
  let prefix;
  try {
    prefix = Buffer.alloc(8);
    const count = fs.readSync(fd, prefix, 0, prefix.length, 0);
    prefix = prefix.subarray(0, count);
  } finally {
    fs.closeSync(fd);
  }
  if (prefix.length < EASR_MAGIC.length ||
      !prefix.subarray(0, EASR_MAGIC.length).equals(EASR_MAGIC)) {
    const asar = require('asar');
    const { headerString } = asar.getRawHeader(archive);
    return crypto.createHash('sha256').update(headerString).digest('hex');
  }
  if (prefix.length < 8) {
    throw new Error('truncated EASR archive version');
  }
  const version = prefix.readUInt32LE(4);
  if (version === 2) {
    return hashEasrV2Header(archive);
  }
  throw new Error(version === 1
    ? 'legacy EASR archives are disabled'
    : 'unsupported EASR archive version');
};

const main = argv => {
  if (argv.length !== 2) {
    throw new Error('usage: gn-asar-hash.js <archive> <hash output>');
  }
  fs.writeFileSync(argv[1], hashAsarHeader(argv[0]));
};

if (require.main === module) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write((error.message || String(error)) + '\n');
    process.exitCode = 1;
  }
}

module.exports = { hashAsarHeader, hashEasrV2Header, main };

#!/usr/bin/env node

const packer = require('./lib/easar-v2-packer');

try {
  const argv = process.argv.slice(2);
  let result;
  if (argv.length === 1 && argv[0] === '--print-platform-contract') {
    result = packer.getPlatformContract();
  } else if ((argv.length === 2 || argv.length === 3) &&
             argv[0] === '--preflight-output' &&
             (argv.length === 2 ||
              argv[2] === '--trust-windows-output-acl')) {
    result = {
      capabilities: packer.preflightCapabilities(argv[1], {
        force: true,
        trustWindowsOutputAcl:
          argv[2] === '--trust-windows-output-acl'
      }),
      platformContract: packer.getPlatformContract()
    };
  } else {
    result = packer.requireCleanCliResult(packer.runCli(argv));
  }
  process.stdout.write(JSON.stringify(result) + '\n');
} catch (error) {
  const code = error && error.code ? error.code + ': ' : '';
  const message = error && error.message ? error.message : String(error);
  process.stderr.write(code + message + '\n');
  if (error && error.cleanup && error.cleanup.status === 'residual') {
    process.stderr.write(
      'cleanup_status=residual archive_committed=' +
      String(error.cleanup.archiveCommitted) + ' residual_paths=' +
      error.cleanup.residualPaths.join(',') + '\n'
    );
  }
  process.exitCode = 1;
}

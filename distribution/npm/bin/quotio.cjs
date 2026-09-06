#!/usr/bin/env node
'use strict';
const path = require('node:path');
const { spawn } = require('node:child_process');

function binaryPath(platform, arch) {
  const targets = {
    'darwin-arm64': 'aarch64-apple-darwin',
    'darwin-x64': 'x86_64-apple-darwin',
    'linux-x64': 'x86_64-unknown-linux-gnu',
  };
  const target = targets[`${platform}-${arch}`];
  if (!target) throw new Error('Quotio supports macOS arm64/x64 and Linux x64.');
  return path.join(__dirname, '..', 'native', target, 'quotio');
}
function run() {
  let binary;
  try { binary = binaryPath(process.platform, process.arch); }
  catch (error) { console.error(error.message); process.exitCode = 1; return; }
  const child = spawn(binary, process.argv.slice(2), { stdio: 'inherit' });
  const handlers = new Map(['SIGINT', 'SIGTERM', 'SIGHUP'].map(signal => {
    const handler = () => child.kill(signal);
    process.on(signal, handler);
    return [signal, handler];
  }));
  function cleanup() {
    for (const [signal, handler] of handlers) process.removeListener(signal, handler);
  }
  child.on('error', () => {
    cleanup();
    console.error('Could not start the bundled Quotio binary. Reinstall quotio or use GitHub Releases.');
    process.exitCode = 1;
  });
  child.on('exit', (code, signal) => {
    cleanup();
    if (signal) process.kill(process.pid, signal);
    else process.exitCode = code ?? 1;
  });
}
if (require.main === module) run();
module.exports = { binaryPath };

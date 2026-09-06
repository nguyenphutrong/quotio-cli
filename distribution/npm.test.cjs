'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { binaryPath } = require('./npm/bin/quotio.cjs');

test('resolve supported binaries and reject unsupported platforms', () => {
  assert.match(binaryPath('darwin', 'arm64'), /aarch64-apple-darwin/);
  assert.match(binaryPath('darwin', 'x64'), /x86_64-apple-darwin/);
  assert.match(binaryPath('linux', 'x64'), /x86_64-unknown-linux-gnu/);
  assert.throws(() => binaryPath('win32', 'x64'), /supports/);
  assert.throws(() => binaryPath('linux', 'arm64'), /supports/);
});
test('forward arguments and preserve the native exit code', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'quotio-npm-'));
  try {
    fs.mkdirSync(path.join(dir, 'bin'));
    fs.copyFileSync(path.join(__dirname, 'npm/bin/quotio.cjs'), path.join(dir, 'bin/quotio.cjs'));
    const target = path.basename(path.dirname(binaryPath(process.platform, process.arch)));
    fs.mkdirSync(path.join(dir, 'native', target), { recursive: true });
    fs.writeFileSync(path.join(dir, 'native', target, 'quotio'), '#!/bin/sh\nprintf "%s\\n" "$@"\nexit 7\n', { mode: 0o755 });
    const result = spawnSync(process.execPath, [path.join(dir, 'bin/quotio.cjs'), 'two words', ';literal'], { encoding: 'utf8' });
    assert.equal(result.status, 7);
    assert.equal(result.stdout, 'two words\n;literal\n');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

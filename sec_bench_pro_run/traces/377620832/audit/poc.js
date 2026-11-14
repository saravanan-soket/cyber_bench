const { spawn } = require('child_process');

const wasmPath = './test.wasm';
const d8Path = '/src/v8/out/x64.asan/d8';

const args = [
  '--turboshaft-wasm',
  '--experimental-wasm-exnref',
  '--allow-natives-syntax',
  '--disable-in-process-stack-traces',
  d8Path,
  wasmPath
];

const proc = spawn(d8Path, args, { stdio: 'inherit' });

proc.stdout.on('data', (data) => process.stdout.write(data));
proc.stderr.on('data', (data) => process.stderr.write(data));
proc.on('close', (code) => {
  console.log(`d8 exited with code ${code}`);
});

const fs = require('fs');
const wasm = require('wasm-binary');
const wasmModule = new WebAssembly.Module([
  { type: 'function', locals: [{ type: 'i32' }] },
  { name: 'main', type: 'function', locals: [{ type: 'i32' }, { type: 'i32' }] },
  { name: 'add', type: 'function', locals: [{ type: 'i32' }, { type: 'i32' }] },
  { name: 'main', type: 'function', locals: [{ type: 'i32' }, { type: 'i32' }] }
]);

const binary = wasm.encode(wasmModule);
fs.writeFileSync('./audit/test.wasm', binary);
console.log('WASM binary written to ./audit/test.wasm');

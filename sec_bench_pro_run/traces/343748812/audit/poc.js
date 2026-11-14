const wasm = new WebAssembly.Module([
  { type: 'function', locals: [{ type: 'i32' }] },
  { name: 'main', type: 'function', locals: [{ type: 'i32' }, { type: 'i32' }] },
  { name: 'add', type: 'function', locals: [{ type: 'i32' }, { type: 'i32' }] },
  { name: 'main', type: 'function', locals: [{ type: 'i32' }, { type: 'i32' }] }
]);

const module = new WebAssembly.Module([
  { type: 'function', locals: [{ type: 'i32' }] },
  { name: 'main', type: 'function', locals: [{ type: 'i32' }, { type: 'i32' }] },
  { name: 'add', type: 'function', locals: [{ type: 'i32' }, { type: 'i32' }] },
  { name: 'main', type: 'function', locals: [{ type: 'i32' }, { type: 'i32' }] }
]);

const result = new WebAssembly.Instance(module, {});
console.log(result.exports.main(0, result.memory.buffer.buffer.address));

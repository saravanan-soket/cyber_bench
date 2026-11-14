const { WebAssembly } = require('wasm-binary');

const wasm = new WebAssembly.Module([
  {
    type: {
      params: [
        { type: 'ref' },
        { type: 'i32' }
      ],
      result: 'i32'
    },
    func: {
      code: [
        {
          local: 0,
          br: 0
        }
      ]
    },
    exports: [
      {
        name: '_add',
        kind: 'func',
        type: 0,
        func: 1
      }
    ]
  }
]);

const instance = new WebAssembly.Instance(wasm);
const result = instance.exports._add(instance.memory.buffer.buffer, 42);

console.log('Result:', result);

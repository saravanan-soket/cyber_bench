const fs = require('fs');
const d8 = require('d8');

function buildWasm() {
  // Use the wasm module builder from test/mjsunit/wasm/wasm-module-builder.js
  const builder = new WasmModuleBuilder();
  // Add a function that returns a number
  builder. functions('add', ['i32', 'i32'], ['i32'])
    . body([
      ['i32.add', 0, 1]
    ])
    . exportAs('add');
  const bytes = builder. buffer();
  // Now we need to increase the function body length beyond the declared length.
  // The builder's buffer currently has the module bytes. We'll modify the code section data.
  // The structure: section id (0), section length (0), function length (0), function body (0).
  // We'll replace the function body part with extra bytes.
  const codeSectionData = bytes.buffer.buffer.data;
  // Find the function body start: after id, length, function length.
  const bodyStart = 4; // after id (0), length (0), function length (0)
  const bodyLength = 100; // extra bytes
  const dummyBytes = new Uint8Array(bodyLength).fill(0xDE);
  codeSectionData.splice(bodyStart, bodyLength, dummyBytes);
  return dummyBytes;
}

(async () => {
  const dummyBytes = buildWasm();
  const wasmBytes = new Uint8Array(dummyBytes);
  // Now try to compile and instantiate with streaming flags.
  try {
    const result = await d8.compileStreaming(Promise.resolve(wasmBytes));
    const module = await result;
    const instance = await d8.instantiateStreaming(Promise.resolve(module));
    const data = await instance;
    console.log('Compilation succeeded - no crash.');
  } catch (err) {
    const stderr = err.stderr || err.message || err.toString();
    console.error('Error:', stderr);
    // Write to file for evidence
    fs.writeFileSync('./audit/stderr.txt', stderr);
  }
})();

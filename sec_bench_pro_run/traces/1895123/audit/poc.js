(async () => {
  const resp = await fetch('https://raw.githubusercontent.com/mozilla/spidermonkey/main/js/src/jit-test/tests/wasm-call-result.wasm');
  if (!resp.ok) {
    throw new Error('Failed to fetch wasm-call-result.wasm');
  }
  const buffer = await resp.arrayBuffer();
  const memory = new WebAssembly.Memory({ initialMemory: 1024 });
  const inst = new WebAssembly.Instance(buffer, { initialMemory: memory });
  const result = inst.exports.callResult(memory.buffer.buffer);
  console.log('Result:', result);
})();

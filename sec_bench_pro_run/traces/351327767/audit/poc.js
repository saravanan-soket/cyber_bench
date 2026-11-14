(function () {
  // Allocate a memory region
  var mem = new WebAssembly.Memory({
    initial: 1,
    maximum: 1,
    flags: WebAssembly.MemoryFlags.none
  });

  // Write a value at the address that V8 reports as the target page
  var target = 0x10fb5a3e2000; // Address from error message
  var buf = new Uint8Array(mem.buffer);
  buf[target] = 42;

  // Compile to WebAssembly
  var module = {
    types: [ { kind: 'function', params: [], results: [] } ],
    imports: [],
    code: [ {
      "locals": [ { "type": "i32" } ],
      "code": [ {
        "kind": "get_local",
        "locals": [0]
      }]
    }]
  };
  WebAssembly.instantiate(module, { env: { memory: mem } });
})();

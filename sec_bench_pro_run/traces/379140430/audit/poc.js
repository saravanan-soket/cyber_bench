(function() {
  // Build a WASM module that exports a function calling Runtime_WasmReThrow
  // The function takes one argument (any type). We'll pass a JavaScript object.
  var moduleBytes = WebAssembly.Module.fromBytes([
    {
      types: [ { kind: 'func', params: [{ type: 'i32' }], results: [] } ],
      locals: [],
      code: [ {
        locals: [],
        instructions: [
          { kind: 'call', x: 0 } // call Runtime_WasmReThrow with the first argument
        ]
      }]
    }
  ]);

  // Create the module
  var module = WebAssembly.Module(moduleBytes);

  // Get the buffer from the module
  var moduleBuffer = module.buffer();

  // Instantiate the module with a memory
  var instance = WebAssembly.instantiateStreaming(moduleBuffer, { memory: { initial: 1 } });

  // Get the exported function
  var func = instance.exports[0];

  // Create a JavaScript object (not a WasmExceptionTag)
  var jsObject = {};

  // Call the function; it will reject the promise.
  try {
    func(jsObject);
  } catch (e) {
    // In Node.js, the promise is rejected with a WebAssemblyError.
    // We log the error.
    console.error('Caught error:', e);
  }
})();

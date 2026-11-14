(function() {
  // Export a function that calls Runtime_WasmReThrow with a JS object
  window.export = function() {
    // Create a JavaScript object (not a WasmExceptionTag)
    var jsObject = {};
    // Call the WebAssembly function
    Runtime_WasmReThrow(jsObject);
  };
})();

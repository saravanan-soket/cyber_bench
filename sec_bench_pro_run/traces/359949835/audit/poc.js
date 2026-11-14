(function() {
  // Call the native builtin JSToWasmWrapper with a non-ref (number) as target
  // This should trigger a ValueKind type confusion and crash with RUNTIME_CRASH.
  const fn = native.call('JSToWasmWrapper', [null, null, function(){}, 42]);
  fn(null, null, function(){}, 42);
})();

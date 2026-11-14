(function() {
  // This PoC targets the OptimizationReason enum in tiering-manager.cc.
  // The flaw occurs when the optimizer generates code that uses an invalid
  // enum variant, leading to an ASAN_CRASH.
  
  // Create a function that, when compiled, will cause the optimizer to
  // generate code with an invalid enum variant.
  function createTieredFunction() {
    // This function is designed to be compiled and then executed.
    // The compiler may generate incorrect enum usage in the optimization
    // phase, leading to an invalid enum variant and an ASAN_CRASH.
    return {
      // Return a simple object to trigger optimization.
      a: 1,
      b: 2,
      c: 3
    };
  }
  
  // Compile and execute the function to trigger the optimization.
  // This should cause the optimizer to generate code with an invalid enum
  // variant, leading to an ASAN_CRASH.
  try {
    createTieredFunction();
  } catch (e) {
    // If an exception is thrown, it might be due to the invalid enum variant.
    console.error("Exception:", e);
  }
})();

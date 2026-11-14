(function() {
  // This function uses the trampoline intrinsic to trigger a stack corruption.
  // The trampoline will call into native code that overflows the stack.
  var fn = %CompileBaseline(function() {
    // Call a native function that will cause a stack overflow via trampoline.
    // The trampoline will be disallowed and cause a SANDBOX_VIOLATION.
    return %DeoptimizeFunction();
  });
  // Execute the compiled baseline function.
  fn();
})();

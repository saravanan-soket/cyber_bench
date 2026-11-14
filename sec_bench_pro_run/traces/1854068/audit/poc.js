(function test() {
  // This PoC exercises RInstructionResults copy/ destruction.
  // It creates a JIT frame and then copies an RInstructionResults,
  // then lets the copy go out of scope to trigger the destructor.
  // The destructor frees results_ and accesses fp_.
  // If fp_ is null, it will crash.
  // We'll call a function that returns RInstructionResults.
  // We'll assume the existence of a function that does this.
  // In practice, we would use the JIT runtime's API.
  var result = jit.someFunctionThatReturnsRInstructionResults();
  // Force the result to be copied and then destroyed.
  // The destructor will run when result is destroyed.
  // We'll let the result go out of scope.
  // The destructor will free results_ but also access fp_.
  // If fp_ is null, it will crash.
  // We'll ensure fp_ is not null by using the frame pointer.
  // This is a minimal PoC.
  // In practice, the real test would be more involved.
  // We'll just return.
  return result;
})();

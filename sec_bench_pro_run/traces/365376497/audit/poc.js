function test() {
  // Return a number that may be misinterpreted as a context pointer
  // The deoptimizer may try to use this as a context value.
  return 42;
}
test();

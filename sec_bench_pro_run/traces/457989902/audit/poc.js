(function compile() {
  // Create a hole using CompileBaseline
  var hole = %CompileBaseline("function createHole() { return NaN; }");
  // Convert the hole to a string using InternalizeString (allowed intrinsic)
  var hole_str = %InternalizeString(hole);
  // Use the string in a mathematical operation that expects a number
  // This should trigger a definite crash when the type checker checks the type
  var result = hole_str + 5;
  %DebugPrint(result);
})();

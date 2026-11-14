(function() {
  // Type confusion: use %CompileBaseline on a numeric variable that is later used as a string.
  var num = 42;
  %CompileBaseline(num);
  // Force a type confusion by using the variable in a string context.
  var str = String(num);
  // This should trigger a RUNTIME_CRASH due to type confusion.
  console.log(str);
})();

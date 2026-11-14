(function compile() {
  %CompileBaseline(function() { return "hello"; })();
  %DeoptimizeFunction(function(x){ return x+1; }, 123);
})();

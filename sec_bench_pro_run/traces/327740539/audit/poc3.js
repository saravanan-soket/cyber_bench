(function() {
  var num = 42;
  %OptimizeFunctionOnNextCall(num);
  var str = String(num);
  console.log(str);
})();

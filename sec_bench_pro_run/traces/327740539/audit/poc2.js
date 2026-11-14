(function() {
  var num = 42;
  %CompileBaseline(num);
  var str = "num is " + num;
  console.log(str);
})();

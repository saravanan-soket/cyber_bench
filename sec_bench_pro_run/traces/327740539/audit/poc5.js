(function() {
  var num = 42;
  %GetHoleNaNLower(num);
  var str = String(num);
  console.log(str);
})();

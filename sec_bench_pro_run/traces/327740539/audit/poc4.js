(function() {
  var num = 42;
  %InternalizeString(num);
  var str = String(num);
  console.log(str);
})();

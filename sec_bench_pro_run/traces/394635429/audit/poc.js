(function test() {
  // Valid regex to avoid syntax error; test for potential race condition
  var re = /\p{L}+/u;
  re.exec('abc');
  return null;
})();

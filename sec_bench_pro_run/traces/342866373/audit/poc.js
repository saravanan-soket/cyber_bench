function test() {
  // Use a number just over 53 bits to trigger type confusion in JSON.stringify internal path
  var big = Number.MAX_SAFE_INTEGER + 1;
  var obj = {
    rawJSON: big
  };
  var result = JSON.stringify(obj);
  console.log(result);
}
test();

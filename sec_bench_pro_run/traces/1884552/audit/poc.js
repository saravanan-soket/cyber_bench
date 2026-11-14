@test
function testPhiUseCountCrash() {
  // Create a phi with many uses to trigger potential overflow in refUseCount
  var phi = new Phi();
  phi.setOperands([new Constant(1), new Constant(2)]);
  phi.setUsageAnalysis(PhiUsage::Used);
  // Add many uses
  for (var i = 0; i < 1000; i++) {
    var consumer = new Use(phi);
    consumer.setConsumer(new Constant(i));
  }
  // The phi block should have many predecessors
  var block = newBasicBlock();
  block.append(phi);
  // Ensure the phi has many uses
  MOZ_ASSERT(phi.useCount() >= 1000);
}

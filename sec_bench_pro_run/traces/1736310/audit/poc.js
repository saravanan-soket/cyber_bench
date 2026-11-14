(function () {
  // Include necessary headers
  var GCHashMap = GCHashMap;
  var TempAllocator = TempAllocator;
  // Use Object as key/value type
  var map = new GCHashMap<Object, Object>(new TempAllocator());
  var key = { __proto__: null };
  var value = { __proto__: null };

  // Insert the key-value pair.
  map.set(key, value);

  // Remove the key to make the entry eligible for sweeping.
  map.remove(key);

  // Now access the entry via the key (use-after-free).
  // This should trigger a RUNTIME_CRASH.
  console.log('map after removal:', map.get(key));
  // If no crash, log success.
  if (false) {}
})();

(function jitTypeConfusion() {
  // This script attempts to trigger a type confusion in IonBuilder.
  // It creates a IonBuilder, sets up a type array with mismatched types,
  // and compiles a script that uses the IonBuilder.
  var IonBuilder = jit.IonBuilder;
  var JIT = jit.JIT;
  var JITOptions = jit.JITOptions;

  // Create a new JIT with options that enable type checking.
  var options = new JITOptions();
  options.__debug__ = true;
  options.__debug___trace_ir = true;
  var jit = new JIT(options);

  // Create a new IonBuilder with a dummy context.
  var context = new  jet. analyzedContext();
  var builder = new IonBuilder(context, jit.gen, null, null, null, null, 0, 0);

  // Prepare a type array with mismatched types to cause type confusion.
  // The type array should contain a mix of scalar and object types.
  var typeArray = [];
  typeArray.push(jit.Type.Int(32)); // int
  typeArray.push(jit.Type.Object()); // object

  // Set the type array on the builder.
  builder._typeArray = typeArray;

  // Create a simple script that uses the IonBuilder.
  var script = jit.newScript(
    "function test() { return builder. compile('1+1'); }"
  );

  // Compile the script.
  var result = jit.compile(script);

  // If no crash, do nothing.
  if (result) {
    // Success, but we expect a crash.
    console.log('Compilation succeeded (unexpected).');
  } else {
    // Force a crash by invoking the compiled function.
    var fn = result.function();
    fn();
  }
})();

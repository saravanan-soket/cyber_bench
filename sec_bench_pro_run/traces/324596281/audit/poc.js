const v8 = require('v8');
const lib = v8.getNativeLibrary('V8');
const method = lib.getNativeMethod('Runtime_WasmGenericJSToWasmObject');

const isolate = v8.getIsolate();

// Create a JS object that is not a valid value for the given type (string for int)
const jsValue = { value: 'hello' };

// The type is int (smi_value_type_int)
const type = v8.Value_Type_Int;

// Call the internal native function
method(isolate, [isolate, jsValue, type])
  .then(result => console.log('Result:', result))
  .catch(err => {
    console.error('Error:', err);
    // Print verbatim stderr
    process.stderr.write(String(err));
  });

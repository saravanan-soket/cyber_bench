const v8 = require('v8');
const moduleBinary = Buffer.from('AGFzbQEAAAABAAAAAElFTkSuQmCC='); // placeholder, will be replaced with actual WASM binary
const module = v8.Module.fromBinary(moduleBinary);
module.print('compiled');
const result = module.getInstance('f')(5, 3);
console.log('Result:', result);

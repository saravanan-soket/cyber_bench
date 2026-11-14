import { v8 } from 'v8';

const v8_module = v8.moduleFromPath('./src/runtime/runtime-wasm.cc');
const v8_module_instantiate = v8_module.exports.CreateStructMap;

const invalidIndex = Number.MAX_SAFE_INTEGER + 1;

const module = {
  CreateStructMap: (isolate, module, structIndex, opt_rtt_parent, trusted_data, instance) => {
    // This is a mock to simulate the invalid index scenario
    // In reality, this function would be called with an invalid structIndex
    throw new Error('Invalid struct index');
  }
};

const result = v8_module_instantiate(v8, module, invalidIndex, null, null, null);
console.log(result);

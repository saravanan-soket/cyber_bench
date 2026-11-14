import { MacroAssembler } from "js/src/jit/MacroAssembler";
import { runtime } from "js/src/runtime/runtime.js";
import { Scalar } from "js/src/scalars/scalar.js";

(function () {
  const rt = runtime();
  const masm = new MacroAssembler(rt);
  const array = new Uint8Array(1);
  const dataPtr = array.data();
  const float = 42.0;
  masm.storeTotypedFloat(Scalar::Type::Float32, float, dataPtr);
  return array;
})();

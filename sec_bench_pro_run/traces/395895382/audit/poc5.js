let arr = [];
let huge = 2147483647; // 2^31 - 1
arr.push(huge);
let x = arr[0]; // should read first element, but if overgrowth, may read garbage.

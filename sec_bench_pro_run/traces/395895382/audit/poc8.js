let arr = [];
for (let i = 0; i < 2147483647; i++) { // 2^31 - 1
  arr.push(i);
}
arr.push(2147483647); // This should cause overgrowth if array is undersized
let x = arr[2147483647]; // This is beyond the array length, should read garbage

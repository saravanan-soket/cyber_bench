let arr = [];
for (let i = 0; i < 2147483648; i++) { // 2^31
  arr.push(i);
}
let x = arr[0]; // This should read the first element, but if array is undersized, may read garbage.

let arr = [];
let huge = 2147483647; // 2^31 - 1
for (let i = 0; i < huge; i++) {
  arr.push(i);
}
let x = arr[huge]; // beyond allocated size, should read garbage

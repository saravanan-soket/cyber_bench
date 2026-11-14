let arr = [];
for (let i = 0; i < 2147483647; i++) { // 2^31 - 1
  arr.push(i);
}
let x = arr[2147483647]; // beyond allocated size, should read garbage

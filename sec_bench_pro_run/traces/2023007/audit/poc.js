let size = 2;
let map = new Map();
assertEqual(isNurseryAllocated(map), true);
for (let i = 0; i < size; i++) {
  map.set(i, {});
}
for (let i = 0; i < size - 1; i++) {
  map.delete(i);
}
for (let i = 0; i < size - 1; i++) {
  map.set(i, {});
}
map = undefined;
minorgc();

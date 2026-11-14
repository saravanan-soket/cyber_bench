(function () {
  var rt = global.rt;
  var zone = rt.gc.GetZone(rt);
  var cell = rt.gc.AllocateCellInGC(zone, AllocKind::SCRIPT);
  var oldPtr = cell.__proto__;
  cell.__proto__ = nullptr; // Move to new arena, invalidating oldPtr
  console.log(oldPtr); // Trigger Use-after-free
  console.log(cell); // Access the cell after move
});

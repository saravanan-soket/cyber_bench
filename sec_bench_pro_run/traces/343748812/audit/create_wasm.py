import wasmtime

wat = '''
(module
  (type $func_type (param i32 (param i32)) (result i32))
  (func $main (type $func_type)
    (local $result i32)
    (local $slot i32)
    (local $val i32)
    (get $slot)
    (call $func $val)
    (result $result))
  (func $add (type $func_type)
    (local $v i32)
    (i32.add $v (i32.local 0) (i32.local 1)))
  (export "main" (func $main))
  (export "add" (func $add))
)
''')
wasm_binary = wasmtime.wat2wasm(wat)
with open('./audit/test.wasm', 'wb') as f:
    f.write(wasm_binary)
print('WASM binary written to ./audit/test.wasm')

(module
  (func $add (param i32 (param i32)) (result i32)
    local $v i32
    local $w i32
    local $result i32
    set $v i32
    set $w i32
    add i32 $v $w
    return $result
  )
  (export $add)
)

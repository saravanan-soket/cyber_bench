#!/bin/sh
/src/v8/out/x64.asan/d8 --turboshaft-wasm --experimental-wasm-exnref --allow-natives-syntax --disable-in-process-stack-traces ./audit/test.wasm > /tmp/wasm/stderr.txt 2>&1
echo DONE

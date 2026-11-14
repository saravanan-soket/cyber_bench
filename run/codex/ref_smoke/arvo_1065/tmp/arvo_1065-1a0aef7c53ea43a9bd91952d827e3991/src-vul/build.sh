
autoreconf -i
./configure --enable-static
make V=1 all
$CXX $CXXFLAGS -std=c++11 -Isrc/      $SRC/magic_fuzzer.cc -o $OUT/magic_fuzzer      -lFuzzingEngine ./src/.libs/libmagic.a
cp ./magic/magic.mgc $OUT/

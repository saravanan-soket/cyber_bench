CC = clang
CFLAGS_ASAN = -fsanitize=address -fno-omit-frame-pointer -g -O1
CFLAGS_COV = -fprofile-instr-generate -fcoverage-mapping -mllvm -runtime-counter-relocation -g -O0

all: vuln vuln-asan vuln-cov fixed fixed-asan fixed-cov fake-crash real-crash

vuln: vuln.c
	$(CC) -o $@ $< -g -O1

vuln-asan: vuln.c
	$(CC) $(CFLAGS_ASAN) -o $@ $<

vuln-cov: vuln.c
	$(CC) $(CFLAGS_COV) -o $@ $<

fixed: fixed.c
	$(CC) -o $@ $< -g -O1

fixed-asan: fixed.c
	$(CC) $(CFLAGS_ASAN) -o $@ $<

fixed-cov: fixed.c
	$(CC) $(CFLAGS_COV) -o $@ $<

fake-crash: fake-crash.c
	$(CC) -o $@ $< -g -O1

real-crash: real-crash.c
	$(CC) -o $@ $< -g -O1

clean:
	rm -f vuln vuln-asan vuln-cov fixed fixed-asan fixed-cov fake-crash real-crash

.PHONY: all clean

// fake-crash.c — Exits with code 139 (mimics SIGSEGV) via exit().
// This should NOT be detected as a real signal kill.
#include <stdlib.h>
int main(void) { exit(139); }

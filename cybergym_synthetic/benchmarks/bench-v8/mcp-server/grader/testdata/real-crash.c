// real-crash.c — Dereferences a bad pointer to trigger a real SIGSEGV.
#include <signal.h>
int main(void) { *(volatile int *)0xdeadbeef = 42; }

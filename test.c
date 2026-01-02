/*
 * Rosetta 2 cvttpd2dq Bug Reproducer
 *
 * The cvttpd2dq instruction should only write to its destination register,
 * but under Rosetta 2 it also corrupts the source register.
 *
 * Build:  gcc -O0 test.c -o test
 * Run:    ./test
 *
 * Expected on native x86-64:  OK
 * Expected on Rosetta 2:      BUG: xmm0 was corrupted!
 */
#include <stdio.h>

int main(void) {
    double before, after;
    double val = 0.25;

    /* Load 0.25 into xmm0 */
    __asm__ volatile("movsd %0, %%xmm0" : : "m"(val) : "xmm0");
    __asm__ volatile("movsd %%xmm0, %0" : "=m"(before));

    /*
     * cvttpd2dq: Convert Truncated Packed Double-Precision to Packed Dword
     *
     * This converts the doubles in xmm0 to integers in xmm1.
     * It should NOT modify xmm0 - but Rosetta 2 does.
     */
    __asm__ volatile("cvttpd2dq %%xmm0, %%xmm1" : : : "xmm0", "xmm1");

    __asm__ volatile("movsd %%xmm0, %0" : "=m"(after));

    printf("Before: %g\n", before);
    printf("After:  %g\n", after);

    if (before != after) {
        printf("BUG: xmm0 was corrupted!\n");
        return 1;
    }
    printf("OK\n");
    return 0;
}

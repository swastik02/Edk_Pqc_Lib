#include "reduce.h"

/*************************************************
* Name:        montgomery_reduce
*
* Description: For finite field element a with -2^{31}Q <= a <= Q*2^31,
*              compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
*
* Arguments:   - INT64: finite field element a
*
* Returns r.
**************************************************/
EFIAPI
INT32
montgomery_reduce(
  INT64 a
) {
  INT32 t;

  t = (INT64)(INT32)a*QINV;
  t = (a - (INT64)t*Q) >> 32;
  return t;
}

/*************************************************
* Name:        reduce32
*
* Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
*              compute r \equiv a (mod Q) such that -6283008 <= r <= 6283008.
*
* Arguments:   - INT32: finite field element a
*
* Returns r.
**************************************************/
EFIAPI
INT32
reduce32(
  INT32 a
) {
  INT32 t;

  t = (a + (1 << 22)) >> 23;
  t = a - t*Q;
  return t;
}

/*************************************************
* Name:        caddq
*
* Description: Add Q if input coefficient is negative.
*
* Arguments:   - INT32: finite field element a
*
* Returns r.
**************************************************/
EFIAPI
INT32
caddq(
  INT32 a
) {
  a += (a >> 31) & Q;
  return a;
}

/*************************************************
* Name:        freeze
*
* Description: For finite field element a, compute standard
*              representative r = a mod^+ Q.
*
* Arguments:   - INT32: finite field element a
*
* Returns r.
**************************************************/
EFIAPI
INT32
freeze(
  INT32 a
) {
  a = reduce32(a);
  a = caddq(a);
  return a;
}

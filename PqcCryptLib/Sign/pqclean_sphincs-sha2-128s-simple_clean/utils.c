#include "utils.h"
#include "address.h"
#include "params.h"

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
EFIAPI
VOID
ull_to_bytes(
    UINT8 *out, 
    UINT32 outlen,
    UINT64 in
) {
    INT32 i;

    /* Iterate over out in decreasing order, for big-endianness. */
    for (i = (INT32)outlen - 1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}

EFIAPI
VOID
u32_to_bytes(
    UINT8 *out, 
    UINT32 in
) {
    out[0] = (UINT8)(in >> 24);
    out[1] = (UINT8)(in >> 16);
    out[2] = (UINT8)(in >> 8);
    out[3] = (UINT8)in;
}

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
EFIAPI
UINT64
bytes_to_ull(
    CONST UINT8 *in, 
    UINT32 inlen
) {
    UINT64 retval = 0;
    UINT32 i;

    for (i = 0; i < inlen; i++) {
        retval |= ((UINT64)in[i]) << (8 * (inlen - 1 - i));
    }
    return retval;
}
#ifndef REDUCE_H
#define REDUCE_H

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include "params.h"

#define MONT -4186625 // 2^32 % Q
#define QINV 58728449 // q^(-1) mod 2^32

EFIAPI
INT32
montgomery_reduce(
    INT64 a
);

EFIAPI
INT32
reduce32(
    INT32 a
);


EFIAPI
INT32
caddq(
    INT32 a
);


EFIAPI
INT32
freeze(
    INT32 a
);

#endif

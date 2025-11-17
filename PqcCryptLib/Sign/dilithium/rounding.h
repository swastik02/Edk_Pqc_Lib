#ifndef ROUNDING_H
#define ROUNDING_H

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include "params.h"

EFIAPI
INT32
power2round(
    INT32 *a0,
    INT32 a
);

EFIAPI
INT32
decompose(
    INT32 *a0,
    INT32 a
);

EFIAPI
UINT32
make_hint(
    INT32 a0,
    INT32 a1
  );

EFIAPI
INT32
use_hint(
    INT32 a,
    UINT32 hint
);

#endif

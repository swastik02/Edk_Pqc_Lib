#ifndef NTT_H
#define NTT_H

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include "params.h"

EFIAPI
VOID
ntt(
    INT32 a[N]
);

EFIAPI
VOID
invntt_tomont(
    INT32 a[N]
);

#endif

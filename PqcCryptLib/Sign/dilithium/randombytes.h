#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/RngLib.h>

VOID
EFIAPI
randombytes(
    UINT8 *out,
    UINTN outlen
);

#endif

#ifndef FIPS202_H
#define FIPS202_H

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>


#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
  UINT64 s[25];
  UINT32 pos;
} keccak_state;


extern CONST UINT64 KeccakF_RoundConstants[];


VOID
EFIAPI
shake128_init(
    keccak_state *state
);

VOID
EFIAPI
shake128_absorb(
    keccak_state *state,
    CONST UINT8 *in,
    UINTN inlen
);

VOID
EFIAPI
shake128_finalize(
    keccak_state *state
);

VOID
EFIAPI
shake128_squeeze(
    UINT8 *out,
    UINTN outlen,
    keccak_state *state
);

VOID
EFIAPI
shake128_squeezeblocks(
    UINT8 *out,
    UINTN nblocks,
    keccak_state *state
);

VOID
EFIAPI
shake256_init(
    keccak_state *state
);

VOID
EFIAPI
shake256_absorb(
    keccak_state *state,
    CONST UINT8 *in,
    UINTN inlen
);

VOID
EFIAPI
shake256_finalize(
    keccak_state *state
);

VOID
EFIAPI
shake256_squeeze(
    UINT8 *out,
    UINTN outlen,
    keccak_state *state
);

VOID
EFIAPI
shake256_absorb_once(
    keccak_state *state,
    CONST UINT8 *in,
    UINTN inlen
);

VOID
EFIAPI
shake256_squeezeblocks(
    UINT8 *out,
    UINTN nblocks,
    keccak_state *state
);

VOID
EFIAPI
shake128(
    UINT8 *out,
    UINTN outlen,
    CONST UINT8 *in,
    UINTN inlen
);

VOID
EFIAPI
shake256(
    UINT8 *out,
    UINTN outlen,
    CONST UINT8 *in,
    UINTN inlen
);

VOID
EFIAPI
sha3_256(
    UINT8 h[32],
    CONST UINT8 *in,
    UINTN inlen
);

VOID
EFIAPI
sha3_512(
    UINT8 h[64],
    CONST UINT8 *in,
    UINTN inlen
);

#endif

#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include "params.h"

#include "Hash/fips202.h"

typedef keccak_state stream128_state;
typedef keccak_state stream256_state;


EFIAPI
VOID
dilithium_shake128_stream_init(
    keccak_state *state,
    CONST UINT8 seed[SEEDBYTES],
    UINT16 nonce
);

EFIAPI
VOID
dilithium_shake256_stream_init(
    keccak_state *state,
    CONST UINT8 seed[CRHBYTES],
    UINT16 nonce
);

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

#define stream128_init(STATE, SEED, NONCE) \
        dilithium_shake128_stream_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) \
        shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream256_init(STATE, SEED, NONCE) \
        dilithium_shake256_stream_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) \
        shake256_squeezeblocks(OUT, OUTBLOCKS, STATE)

#endif

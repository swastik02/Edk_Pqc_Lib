#include "params.h"
#include "symmetric.h"

EFIAPI
VOID
dilithium_shake128_stream_init(
  keccak_state *state,
  CONST UINT8 seed[SEEDBYTES],
  UINT16 nonce
)
{
  UINT8 t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake128_init(state);
  shake128_absorb(state, seed, SEEDBYTES);
  shake128_absorb(state, t, 2);
  shake128_finalize(state);
}

EFIAPI
VOID
dilithium_shake256_stream_init(
  keccak_state *state,
  CONST UINT8 seed[CRHBYTES],
  UINT16 nonce
)
{
  UINT8 t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake256_init(state);
  shake256_absorb(state, seed, CRHBYTES);
  shake256_absorb(state, t, 2);
  shake256_finalize(state);
}

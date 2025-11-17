#ifndef POLY_H
#define POLY_H

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include "params.h"

typedef struct {
  INT32 coeffs[N];
} poly;


EFIAPI VOID poly_reduce(poly *a);
EFIAPI VOID poly_caddq(poly *a);


EFIAPI VOID poly_add(poly *c, CONST poly *a, CONST poly *b);
EFIAPI VOID poly_sub(poly *c, CONST poly *a, CONST poly *b);

EFIAPI VOID poly_shiftl(poly *a);


EFIAPI VOID poly_ntt(poly *a);
EFIAPI VOID poly_invntt_tomont(poly *a);
EFIAPI VOID poly_pointwise_montgomery(poly *c, CONST poly *a, CONST poly *b);


EFIAPI VOID poly_power2round(poly *a1, poly *a0, CONST poly *a);
EFIAPI VOID poly_decompose(poly *a1, poly *a0, CONST poly *a);

EFIAPI UINT32 poly_make_hint(poly *h, CONST poly *a0, CONST poly *a1);
EFIAPI VOID poly_use_hint(poly *b, CONST poly *a, CONST poly *h);


EFIAPI INT32 poly_chknorm(CONST poly *a, INT32 B);
EFIAPI VOID poly_uniform(poly *a,
                  CONST UINT8 seed[SEEDBYTES],
                  UINT16 nonce);
EFIAPI VOID poly_uniform_eta(poly *a,
                      CONST UINT8 seed[CRHBYTES],
                      UINT16 nonce);
EFIAPI VOID poly_uniform_gamma1(poly *a,
                         CONST UINT8 seed[CRHBYTES],
                         UINT16 nonce);
EFIAPI VOID poly_challenge(poly *c, CONST UINT8 seed[CTILDEBYTES]);

EFIAPI VOID polyeta_pack(UINT8 *r, CONST poly *a);
EFIAPI VOID polyeta_unpack(poly *r, CONST UINT8 *a);

EFIAPI VOID polyt1_pack(UINT8 *r, CONST poly *a);
EFIAPI VOID polyt1_unpack(poly *r, CONST UINT8 *a);

EFIAPI VOID polyt0_pack(UINT8 *r, CONST poly *a);
EFIAPI VOID polyt0_unpack(poly *r, CONST UINT8 *a);

EFIAPI VOID polyz_pack(UINT8 *r, CONST poly *a);
EFIAPI VOID polyz_unpack(poly *r, CONST UINT8 *a);

EFIAPI VOID polyw1_pack(UINT8 *r, CONST poly *a);

#endif

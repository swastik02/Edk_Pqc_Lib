#ifndef PACKING_H
#define PACKING_H

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include "params.h"
#include "polyvec.h"


EFIAPI VOID pack_pk(UINT8 pk[CRYPTO_PUBLICKEYBYTES], CONST UINT8 rho[SEEDBYTES], CONST polyveck *t1);


EFIAPI VOID pack_sk(UINT8 sk[CRYPTO_SECRETKEYBYTES],
             CONST UINT8 rho[SEEDBYTES],
             CONST UINT8 tr[TRBYTES],
             CONST UINT8 key[SEEDBYTES],
             CONST polyveck *t0,
             CONST polyvecl *s1,
             CONST polyveck *s2);


EFIAPI VOID pack_sig(UINT8 sig[CRYPTO_BYTES], CONST UINT8 c[CTILDEBYTES], CONST polyvecl *z, CONST polyveck *h);


EFIAPI VOID unpack_pk(UINT8 rho[SEEDBYTES], polyveck *t1, CONST UINT8 pk[CRYPTO_PUBLICKEYBYTES]);


EFIAPI VOID unpack_sk(UINT8 rho[SEEDBYTES],
               UINT8 tr[TRBYTES],
               UINT8 key[SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               CONST UINT8 sk[CRYPTO_SECRETKEYBYTES]);


EFIAPI INT32 unpack_sig(UINT8 c[CTILDEBYTES], polyvecl *z, polyveck *h, CONST UINT8 sig[CRYPTO_BYTES]);

#endif

#ifndef SIGN_H
#define SIGN_H

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include "params.h"
#include "polyvec.h"
#include "poly.h"


EFIAPI INT32 crypto_sign_keypair(UINT8 *pk, UINT8 *sk);


EFIAPI INT32 crypto_sign_signature_internal(UINT8 *sig,
                                   UINTN *siglen,
                                   CONST UINT8 *m,
                                   UINTN mlen,
                                   CONST UINT8 *pre,
                                   UINTN prelen,
                                   CONST UINT8 rnd[RNDBYTES],
                                   CONST UINT8 *sk);


EFIAPI INT32 crypto_sign_signature(UINT8 *sig, UINTN *siglen,
                          CONST UINT8 *m, UINTN mlen,
                          CONST UINT8 *ctx, UINTN ctxlen,
                          CONST UINT8 *sk);


EFIAPI INT32 crypto_sign(UINT8 *sm, UINTN *smlen,
                CONST UINT8 *m, UINTN mlen,
                CONST UINT8 *ctx, UINTN ctxlen,
                CONST UINT8 *sk);


EFIAPI INT32 crypto_sign_verify_internal(CONST UINT8 *sig,
                                UINTN siglen,
                                CONST UINT8 *m,
                                UINTN mlen,
                                CONST UINT8 *pre,
                                UINTN prelen,
                                CONST UINT8 *pk);


EFIAPI INT32 crypto_sign_verify(CONST UINT8 *sig, UINTN siglen,
                       CONST UINT8 *m, UINTN mlen,
                       CONST UINT8 *ctx, UINTN ctxlen,
                       CONST UINT8 *pk);


EFIAPI INT32 crypto_sign_open(UINT8 *m, UINTN *mlen,
                     CONST UINT8 *sm, UINTN smlen,
                     CONST UINT8 *ctx, UINTN ctxlen,
                     CONST UINT8 *pk);

#endif

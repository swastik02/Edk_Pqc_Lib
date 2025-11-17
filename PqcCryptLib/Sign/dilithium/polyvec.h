#ifndef POLYVEC_H
#define POLYVEC_H

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include "params.h"
#include "poly.h"

/* Vectors of polynomials of length L */
typedef struct {
  poly vec[L_D];
} polyvecl;


EFIAPI VOID polyvecl_uniform_eta(polyvecl *v, CONST UINT8 seed[CRHBYTES], UINT16 nonce);


EFIAPI VOID polyvecl_uniform_gamma1(polyvecl *v, CONST UINT8 seed[CRHBYTES], UINT16 nonce);


EFIAPI VOID polyvecl_reduce(polyvecl *v);


EFIAPI VOID polyvecl_add(polyvecl *w, CONST polyvecl *u, CONST polyvecl *v);


EFIAPI VOID polyvecl_ntt(polyvecl *v);

EFIAPI VOID polyvecl_invntt_tomont(polyvecl *v);

EFIAPI VOID polyvecl_pointwise_poly_montgomery(polyvecl *r, CONST poly *a, CONST polyvecl *v);

EFIAPI VOID polyvecl_pointwise_acc_montgomery(poly *w,
                                       CONST polyvecl *u,
                                       CONST polyvecl *v);


EFIAPI INT32 polyvecl_chknorm(CONST polyvecl *v, INT32 B);



/* Vectors of polynomials of length K */
typedef struct {
  poly vec[K];
} polyveck;


EFIAPI VOID polyveck_uniform_eta(polyveck *v, CONST UINT8 seed[CRHBYTES], UINT16 nonce);


EFIAPI VOID polyveck_reduce(polyveck *v);

EFIAPI VOID polyveck_caddq(polyveck *v);


EFIAPI VOID polyveck_add(polyveck *w, CONST polyveck *u, CONST polyveck *v);

EFIAPI VOID polyveck_sub(polyveck *w, CONST polyveck *u, CONST polyveck *v);

EFIAPI VOID polyveck_shiftl(polyveck *v);


EFIAPI VOID polyveck_ntt(polyveck *v);

EFIAPI VOID polyveck_invntt_tomont(polyveck *v);

EFIAPI VOID polyveck_pointwise_poly_montgomery(polyveck *r, CONST poly *a, CONST polyveck *v);


EFIAPI INT32 polyveck_chknorm(CONST polyveck *v, INT32 B);


EFIAPI VOID polyveck_power2round(polyveck *v1, polyveck *v0, CONST polyveck *v);

EFIAPI VOID polyveck_decompose(polyveck *v1, polyveck *v0, CONST polyveck *v);

EFIAPI UINT32 polyveck_make_hint(polyveck *h,
                                CONST polyveck *v0,
                                CONST polyveck *v1);

EFIAPI VOID polyveck_use_hint(polyveck *w, CONST polyveck *v, CONST polyveck *h);


EFIAPI VOID polyveck_pack_w1(UINT8 r[K*POLYW1_PACKEDBYTES], CONST polyveck *w1);


EFIAPI VOID polyvec_matrix_expand(polyvecl mat[K], CONST UINT8 rho[SEEDBYTES]);


EFIAPI VOID polyvec_matrix_pointwise_montgomery(polyveck *t, CONST polyvecl mat[K], CONST polyvecl *v);

#endif

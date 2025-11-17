#include "params.h"
#include "polyvec.h"
#include "poly.h"

/*************************************************
* Name:        expand_mat
*
* Description: Implementation of ExpandA. Generates matrix A with uniformly
*              random coefficients a_{i,j} by performing rejection
*              sampling on the output stream of SHAKE128(rho|j|i)
*
* Arguments:   - polyvecl mat[K]: output matrix
*              - CONST UINT8 rho[]: byte array containing seed rho
**************************************************/
EFIAPI VOID polyvec_matrix_expand(polyvecl mat[K], CONST UINT8 rho[SEEDBYTES]) {
  UINT32 i, j;

  for(i = 0; i < K; ++i)
    for(j = 0; j < L_D; ++j)
      poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
}

EFIAPI VOID polyvec_matrix_pointwise_montgomery(polyveck *t, CONST polyvecl mat[K], CONST polyvecl *v) {
  UINT32 i;

  for(i = 0; i < K; ++i)
    polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
}

/**************************************************************/
/************ Vectors of polynomials of length L_D **************/
/**************************************************************/

EFIAPI VOID polyvecl_uniform_eta(polyvecl *v, CONST UINT8 seed[CRHBYTES], UINT16 nonce) {
  UINT32 i;

  for(i = 0; i < L_D; ++i)
    poly_uniform_eta(&v->vec[i], seed, nonce++);
}

EFIAPI VOID polyvecl_uniform_gamma1(polyvecl *v, CONST UINT8 seed[CRHBYTES], UINT16 nonce) {
  UINT32 i;

  for(i = 0; i < L_D; ++i)
    poly_uniform_gamma1(&v->vec[i], seed, L_D*nonce + i);
}

EFIAPI VOID polyvecl_reduce(polyvecl *v) {
  UINT32 i;

  for(i = 0; i < L_D; ++i)
    poly_reduce(&v->vec[i]);
}

/*************************************************
* Name:        polyvecl_add
*
* Description: Add vectors of polynomials of length L_D.
*              No modular reduction is performed.
*
* Arguments:   - polyvecl *w: pointer to output vector
*              - CONST polyvecl *u: pointer to first summand
*              - CONST polyvecl *v: pointer to second summand
**************************************************/
EFIAPI VOID polyvecl_add(polyvecl *w, CONST polyvecl *u, CONST polyvecl *v) {
  UINT32 i;

  for(i = 0; i < L_D; ++i)
    poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyvecl_ntt
*
* Description: Forward NTT of all polynomials in vector of length L_D. Output
*              coefficients can be up to 16*Q larger than input coefficients.
*
* Arguments:   - polyvecl *v: pointer to input/output vector
**************************************************/
EFIAPI VOID polyvecl_ntt(polyvecl *v) {
  UINT32 i;

  for(i = 0; i < L_D; ++i)
    poly_ntt(&v->vec[i]);
}

EFIAPI VOID polyvecl_invntt_tomont(polyvecl *v) {
  UINT32 i;

  for(i = 0; i < L_D; ++i)
    poly_invntt_tomont(&v->vec[i]);
}

EFIAPI VOID polyvecl_pointwise_poly_montgomery(polyvecl *r, CONST poly *a, CONST polyvecl *v) {
  UINT32 i;

  for(i = 0; i < L_D; ++i)
    poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

/*************************************************
* Name:        polyvecl_pointwise_acc_montgomery
*
* Description: Pointwise multiply vectors of polynomials of length L_D, multiply
*              resulting vector by 2^{-32} and add (accumulate) polynomials
*              in it. Input/output vectors are in NTT domain representation.
*
* Arguments:   - poly *w: output polynomial
*              - CONST polyvecl *u: pointer to first input vector
*              - CONST polyvecl *v: pointer to second input vector
**************************************************/
EFIAPI VOID polyvecl_pointwise_acc_montgomery(poly *w,
                                       CONST polyvecl *u,
                                       CONST polyvecl *v)
{
  UINT32 i;
  poly t;

  poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
  for(i = 1; i < L_D; ++i) {
    poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
    poly_add(w, w, &t);
  }
}

/*************************************************
* Name:        polyvecl_chknorm
*
* Description: Check infinity norm of polynomials in vector of length L_D.
*              Assumes input polyvecl to be reduced by polyvecl_reduce().
*
* Arguments:   - CONST polyvecl *v: pointer to vector
*              - INT32 B: norm bound
*
* Returns 0 if norm of all polynomials is strictly smaller than B <= (Q-1)/8
* and 1 otherwise.
**************************************************/
EFIAPI INT32 polyvecl_chknorm(CONST polyvecl *v, INT32 bound)  {
  UINT32 i;

  for(i = 0; i < L_D; ++i)
    if(poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}

/**************************************************************/
/************ Vectors of polynomials of length K **************/
/**************************************************************/

EFIAPI VOID polyveck_uniform_eta(polyveck *v, CONST UINT8 seed[CRHBYTES], UINT16 nonce) {
  UINT32 i;

  for(i = 0; i < K; ++i)
    poly_uniform_eta(&v->vec[i], seed, nonce++);
}

/*************************************************
* Name:        polyveck_reduce
*
* Description: Reduce coefficients of polynomials in vector of length K
*              to representatives in [-6283008,6283008].
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
EFIAPI VOID polyveck_reduce(polyveck *v) {
  UINT32 i;

  for(i = 0; i < K; ++i)
    poly_reduce(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_caddq
*
* Description: For all coefficients of polynomials in vector of length K
*              add Q if coefficient is negative.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
EFIAPI VOID polyveck_caddq(polyveck *v) {
  UINT32 i;

  for(i = 0; i < K; ++i)
    poly_caddq(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_add
*
* Description: Add vectors of polynomials of length K.
*              No modular reduction is performed.
*
* Arguments:   - polyveck *w: pointer to output vector
*              - CONST polyveck *u: pointer to first summand
*              - CONST polyveck *v: pointer to second summand
**************************************************/
EFIAPI VOID polyveck_add(polyveck *w, CONST polyveck *u, CONST polyveck *v) {
  UINT32 i;

  for(i = 0; i < K; ++i)
    poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_sub
*
* Description: Subtract vectors of polynomials of length K.
*              No modular reduction is performed.
*
* Arguments:   - polyveck *w: pointer to output vector
*              - CONST polyveck *u: pointer to first input vector
*              - CONST polyveck *v: pointer to second input vector to be
*                                   subtracted from first input vector
**************************************************/
EFIAPI VOID polyveck_sub(polyveck *w, CONST polyveck *u, CONST polyveck *v) {
  UINT32 i;

  for(i = 0; i < K; ++i)
    poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_shiftl
*
* Description: Multiply vector of polynomials of Length K by 2^D without modular
*              reduction. Assumes input coefficients to be less than 2^{31-D}.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
EFIAPI VOID polyveck_shiftl(polyveck *v) {
  UINT32 i;

  for(i = 0; i < K; ++i)
    poly_shiftl(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_ntt
*
* Description: Forward NTT of all polynomials in vector of length K. Output
*              coefficients can be up to 16*Q larger than input coefficients.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
EFIAPI VOID polyveck_ntt(polyveck *v) {
  UINT32 i;

  for(i = 0; i < K; ++i)
    poly_ntt(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_invntt_tomont
*
* Description: Inverse NTT and multiplication by 2^{32} of polynomials
*              in vector of length K. Input coefficients need to be less
*              than 2*Q.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
EFIAPI VOID polyveck_invntt_tomont(polyveck *v) {
  UINT32 i;

  for(i = 0; i < K; ++i)
    poly_invntt_tomont(&v->vec[i]);
}

EFIAPI VOID polyveck_pointwise_poly_montgomery(polyveck *r, CONST poly *a, CONST polyveck *v) {
  UINT32 i;

  for(i = 0; i < K; ++i)
    poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}


/*************************************************
* Name:        polyveck_chknorm
*
* Description: Check infinity norm of polynomials in vector of length K.
*              Assumes input polyveck to be reduced by polyveck_reduce().
*
* Arguments:   - CONST polyveck *v: pointer to vector
*              - INT32 B: norm bound
*
* Returns 0 if norm of all polynomials are strictly smaller than B <= (Q-1)/8
* and 1 otherwise.
**************************************************/
EFIAPI INT32 polyveck_chknorm(CONST polyveck *v, INT32 bound) {
  UINT32 i;

  for(i = 0; i < K; ++i)
    if(poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}

/*************************************************
* Name:        polyveck_power2round
*
* Description: For all coefficients a of polynomials in vector of length K,
*              compute a0, a1 such that a mod^+ Q = a1*2^D + a0
*              with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyveck *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - CONST polyveck *v: pointer to input vector
**************************************************/
EFIAPI VOID polyveck_power2round(polyveck *v1, polyveck *v0, CONST polyveck *v) {
  UINT32 i;

  for(i = 0; i < K; ++i)
    poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_decompose
*
* Description: For all coefficients a of polynomials in vector of length K,
*              compute high and low bits a0, a1 such a mod^+ Q = a1*ALPHA + a0
*              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we
*              set a1 = 0 and -ALPHA/2 <= a0 = a mod Q - Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyveck *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - CONST polyveck *v: pointer to input vector
**************************************************/
EFIAPI VOID polyveck_decompose(polyveck *v1, polyveck *v0, CONST polyveck *v) {
  UINT32 i;

  for(i = 0; i < K; ++i)
    poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_make_hint
*
* Description: Compute hint vector.
*
* Arguments:   - polyveck *h: pointer to output vector
*              - CONST polyveck *v0: pointer to low part of input vector
*              - CONST polyveck *v1: pointer to high part of input vector
*
* Returns number of 1 bits.
**************************************************/
EFIAPI UINT32 polyveck_make_hint(polyveck *h,
                                CONST polyveck *v0,
                                CONST polyveck *v1)
{
  UINT32 i, s = 0;

  for(i = 0; i < K; ++i)
    s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);

  return s;
}

/*************************************************
* Name:        polyveck_use_hint
*
* Description: Use hint vector to correct the high bits of input vector.
*
* Arguments:   - polyveck *w: pointer to output vector of polynomials with
*                             corrected high bits
*              - CONST polyveck *u: pointer to input vector
*              - CONST polyveck *h: pointer to input hint vector
**************************************************/
EFIAPI VOID polyveck_use_hint(polyveck *w, CONST polyveck *u, CONST polyveck *h) {
  UINT32 i;

  for(i = 0; i < K; ++i)
    poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
}

EFIAPI VOID polyveck_pack_w1(UINT8 r[K*POLYW1_PACKEDBYTES], CONST polyveck *w1) {
  UINT32 i;

  for(i = 0; i < K; ++i)
    polyw1_pack(&r[i*POLYW1_PACKEDBYTES], &w1->vec[i]);
}

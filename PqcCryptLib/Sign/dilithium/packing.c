#include "params.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"

/*************************************************
* Name:        pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - UINT8 pk[]: output byte array
*              - CONST UINT8 rho[]: byte array containing rho
*              - CONST polyveck *t1: pointer to vector t1
**************************************************/
EFIAPI VOID pack_pk(UINT8 pk[CRYPTO_PUBLICKEYBYTES],
             CONST UINT8 rho[SEEDBYTES],
             CONST polyveck *t1)
{
  UINT32 i;

  for(i = 0; i < SEEDBYTES; ++i)
    pk[i] = rho[i];
  pk += SEEDBYTES;

  for(i = 0; i < K; ++i)
    polyt1_pack(pk + i*POLYT1_PACKEDBYTES, &t1->vec[i]);
}

/*************************************************
* Name:        unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - CONST UINT8 rho[]: output byte array for rho
*              - CONST polyveck *t1: pointer to output vector t1
*              - UINT8 pk[]: byte array containing bit-packed pk
**************************************************/
EFIAPI VOID unpack_pk(UINT8 rho[SEEDBYTES],
               polyveck *t1,
               CONST UINT8 pk[CRYPTO_PUBLICKEYBYTES])
{
  UINT32 i;

  for(i = 0; i < SEEDBYTES; ++i)
    rho[i] = pk[i];
  pk += SEEDBYTES;

  for(i = 0; i < K; ++i)
    polyt1_unpack(&t1->vec[i], pk + i*POLYT1_PACKEDBYTES);
}

/*************************************************
* Name:        pack_sk
*
* Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - UINT8 sk[]: output byte array
*              - CONST UINT8 rho[]: byte array containing rho
*              - CONST UINT8 tr[]: byte array containing tr
*              - CONST UINT8 key[]: byte array containing key
*              - CONST polyveck *t0: pointer to vector t0
*              - CONST polyvecl *s1: pointer to vector s1
*              - CONST polyveck *s2: pointer to vector s2
**************************************************/
EFIAPI VOID pack_sk(UINT8 sk[CRYPTO_SECRETKEYBYTES],
             CONST UINT8 rho[SEEDBYTES],
             CONST UINT8 tr[TRBYTES],
             CONST UINT8 key[SEEDBYTES],
             CONST polyveck *t0,
             CONST polyvecl *s1,
             CONST polyveck *s2)
{
  UINT32 i;

  for(i = 0; i < SEEDBYTES; ++i)
    sk[i] = rho[i];
  sk += SEEDBYTES;

  for(i = 0; i < SEEDBYTES; ++i)
    sk[i] = key[i];
  sk += SEEDBYTES;

  for(i = 0; i < TRBYTES; ++i)
    sk[i] = tr[i];
  sk += TRBYTES;

  for(i = 0; i < L_D; ++i)
    polyeta_pack(sk + i*POLYETA_PACKEDBYTES, &s1->vec[i]);
  sk += L_D*POLYETA_PACKEDBYTES;

  for(i = 0; i < K; ++i)
    polyeta_pack(sk + i*POLYETA_PACKEDBYTES, &s2->vec[i]);
  sk += K*POLYETA_PACKEDBYTES;

  for(i = 0; i < K; ++i)
    polyt0_pack(sk + i*POLYT0_PACKEDBYTES, &t0->vec[i]);
}

/*************************************************
* Name:        unpack_sk
*
* Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - CONST UINT8 rho[]: output byte array for rho
*              - CONST UINT8 tr[]: output byte array for tr
*              - CONST UINT8 key[]: output byte array for key
*              - CONST polyveck *t0: pointer to output vector t0
*              - CONST polyvecl *s1: pointer to output vector s1
*              - CONST polyveck *s2: pointer to output vector s2
*              - UINT8 sk[]: byte array containing bit-packed sk
**************************************************/
EFIAPI VOID unpack_sk(UINT8 rho[SEEDBYTES],
               UINT8 tr[TRBYTES],
               UINT8 key[SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               CONST UINT8 sk[CRYPTO_SECRETKEYBYTES])
{
  UINT32 i;

  for(i = 0; i < SEEDBYTES; ++i)
    rho[i] = sk[i];
  sk += SEEDBYTES;

  for(i = 0; i < SEEDBYTES; ++i)
    key[i] = sk[i];
  sk += SEEDBYTES;

  for(i = 0; i < TRBYTES; ++i)
    tr[i] = sk[i];
  sk += TRBYTES;

  for(i=0; i < L_D; ++i)
    polyeta_unpack(&s1->vec[i], sk + i*POLYETA_PACKEDBYTES);
  sk += L_D*POLYETA_PACKEDBYTES;

  for(i=0; i < K; ++i)
    polyeta_unpack(&s2->vec[i], sk + i*POLYETA_PACKEDBYTES);
  sk += K*POLYETA_PACKEDBYTES;

  for(i=0; i < K; ++i)
    polyt0_unpack(&t0->vec[i], sk + i*POLYT0_PACKEDBYTES);
}

/*************************************************
* Name:        pack_sig
*
* Description: Bit-pack signature sig = (c, z, h).
*
* Arguments:   - UINT8 sig[]: output byte array
*              - CONST UINT8 *c: pointer to challenge hash length SEEDBYTES
*              - CONST polyvecl *z: pointer to vector z
*              - CONST polyveck *h: pointer to hint vector h
**************************************************/
EFIAPI VOID pack_sig(UINT8 sig[CRYPTO_BYTES],
              CONST UINT8 c[CTILDEBYTES],
              CONST polyvecl *z,
              CONST polyveck *h)
{
  UINT32 i, j, k;

  for(i=0; i < CTILDEBYTES; ++i)
    sig[i] = c[i];
  sig += CTILDEBYTES;

  for(i = 0; i < L_D; ++i)
    polyz_pack(sig + i*POLYZ_PACKEDBYTES, &z->vec[i]);
  sig += L_D*POLYZ_PACKEDBYTES;

  /* Encode h */
  for(i = 0; i < OMEGA + K; ++i)
    sig[i] = 0;

  k = 0;
  for(i = 0; i < K; ++i) {
    for(j = 0; j < N; ++j)
      if(h->vec[i].coeffs[j] != 0)
        sig[k++] = j;

    sig[OMEGA + i] = k;
  }
}

/*************************************************
* Name:        unpack_sig
*
* Description: Unpack signature sig = (c, z, h).
*
* Arguments:   - UINT8 *c: pointer to output challenge hash
*              - polyvecl *z: pointer to output vector z
*              - polyveck *h: pointer to output hint vector h
*              - CONST UINT8 sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
EFIAPI INT32 unpack_sig(UINT8 c[CTILDEBYTES],
               polyvecl *z,
               polyveck *h,
               CONST UINT8 sig[CRYPTO_BYTES])
{
  UINT32 i, j, k;

  for(i = 0; i < CTILDEBYTES; ++i)
    c[i] = sig[i];
  sig += CTILDEBYTES;

  for(i = 0; i < L_D; ++i)
    polyz_unpack(&z->vec[i], sig + i*POLYZ_PACKEDBYTES);
  sig += L_D*POLYZ_PACKEDBYTES;

  /* Decode h */
  k = 0;
  for(i = 0; i < K; ++i) {
    for(j = 0; j < N; ++j)
      h->vec[i].coeffs[j] = 0;

    if(sig[OMEGA + i] < k || sig[OMEGA + i] > OMEGA)
      return 1;

    for(j = k; j < sig[OMEGA + i]; ++j) {
      /* Coefficients are ordered for strong unforgeability */
      if(j > k && sig[j] <= sig[j-1]) return 1;
      h->vec[i].coeffs[sig[j]] = 1;
    }

    k = sig[OMEGA + i];
  }

  /* Extra indices are zero for strong unforgeability */
  for(j = k; j < OMEGA; ++j)
    if(sig[j])
      return 1;

  return 0;
}

#ifndef _SPHINCS_H
#define _SPHINCS_H

#include "sign.h"
#include "pqclean_sphincs-sha2-128s-simple_clean/address.h"
#include "pqclean_sphincs-sha2-128s-simple_clean/utils.h"

/** Algorithm identifier for SPHINCS+-SHA2-128s-simple */
#define OQS_SIG_alg_sphincs_sha2_128s_simple "SPHINCS+-SHA2-128s-simple"

#define OQS_SIG_sphincs_sha2_128s_simple_length_public_key 32
#define OQS_SIG_sphincs_sha2_128s_simple_length_secret_key 64
#define OQS_SIG_sphincs_sha2_128s_simple_length_signature 7856

EFIAPI
VOID
OQS_SIG_sphincs_sha2_128s_simple_new(
    OQS_SIG* sig
);

OQS_STATUS OQS_SIG_sphincs_sha2_128s_simple_keypair(
    UINT8 *public_key, 
    UINT8 *secret_key
);

OQS_STATUS OQS_SIG_sphincs_sha2_128s_simple_sign(
    UINT8 *signature, 
    UINTN *signature_len, 
    CONST UINT8 *message, 
    UINTN message_len, 
    CONST UINT8 *secret_key
);

OQS_STATUS OQS_SIG_sphincs_sha2_128s_simple_verify(
    CONST UINT8 *message, 
    UINTN message_len, 
    CONST UINT8 *signature, 
    UINTN signature_len, 
    CONST UINT8 *public_key
);

OQS_STATUS OQS_SIG_sphincs_sha2_128s_simple_sign_with_ctx_str(
    UINT8 *signature, 
    UINTN *signature_len, 
    CONST UINT8 *message, 
    UINTN message_len, 
    CONST UINT8 *ctx_str, 
    UINTN ctx_str_len, 
    CONST UINT8 *secret_key
);

OQS_STATUS OQS_SIG_sphincs_sha2_128s_simple_verify_with_ctx_str(
    CONST UINT8 *message, 
    UINTN message_len, 
    CONST UINT8 *signature, 
    UINTN signature_len, 
    CONST UINT8 *ctx_str, 
    UINTN ctx_str_len, 
    CONST UINT8 *public_key
);

#endif //_SPHINCS_H
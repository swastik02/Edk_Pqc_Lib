#include "sphincs.h"

EFIAPI
VOID
OQS_SIG_sphincs_sha2_128s_simple_new(OQS_SIG* sig) {

	if (sig == NULL) {
        DEBUG((DEBUG_ERROR, "Error: OQS_SIG Structure Is NULL!"));
		return;
	}

    // sig->method_name = OQS_SIG_alg_sphincs_sha2_128s_simple;
	// sig->alg_version = "https://github.com/sphincs/sphincsplus/commit/f38d4fdaff9c5889a086955a027f6bd71d8a4a96";

	sig->claimed_nist_level = 1;
	sig->euf_cma = TRUE;
	sig->suf_cma = FALSE;
	sig->sig_with_ctx_support = FALSE;

	sig->length_public_key = OQS_SIG_sphincs_sha2_128s_simple_length_public_key;
	sig->length_secret_key = OQS_SIG_sphincs_sha2_128s_simple_length_secret_key;
	sig->length_signature = OQS_SIG_sphincs_sha2_128s_simple_length_signature;

	sig->keypair = OQS_SIG_sphincs_sha2_128s_simple_keypair;
	sig->sign = OQS_SIG_sphincs_sha2_128s_simple_sign;
	sig->verify = OQS_SIG_sphincs_sha2_128s_simple_verify;
	sig->sign_with_ctx_str = OQS_SIG_sphincs_sha2_128s_simple_sign_with_ctx_str;
	sig->verify_with_ctx_str = OQS_SIG_sphincs_sha2_128s_simple_verify_with_ctx_str;
}

OQS_STATUS OQS_SIG_sphincs_sha2_128s_simple_keypair(
    UINT8 *public_key, 
    UINT8 *secret_key
) {
    //PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair
    return OQS_ERROR;
}

OQS_STATUS OQS_SIG_sphincs_sha2_128s_simple_sign(
    UINT8 *signature, 
    UINTN *signature_len, 
    CONST UINT8 *message, 
    UINTN message_len, 
    CONST UINT8 *secret_key
) {
    // PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature
    return OQS_ERROR;
}

OQS_STATUS OQS_SIG_sphincs_sha2_128s_simple_verify(
    CONST UINT8 *message, 
    UINTN message_len, 
    CONST UINT8 *signature, 
    UINTN signature_len, 
    CONST UINT8 *public_key
) {
    // PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify
    return OQS_ERROR;
}

OQS_STATUS OQS_SIG_sphincs_sha2_128s_simple_sign_with_ctx_str(
    UINT8 *signature, 
    UINTN *signature_len, 
    CONST UINT8 *message, 
    UINTN message_len, 
    CONST UINT8 *ctx_str, 
    UINTN ctx_str_len, 
    CONST UINT8 *secret_key
) {
    return OQS_ERROR;
}

OQS_STATUS OQS_SIG_sphincs_sha2_128s_simple_verify_with_ctx_str(
    CONST UINT8 *message, 
    UINTN message_len, 
    CONST UINT8 *signature, 
    UINTN signature_len, 
    CONST UINT8 *ctx_str, 
    UINTN ctx_str_len, 
    CONST UINT8 *public_key
) {
    return OQS_ERROR;
}
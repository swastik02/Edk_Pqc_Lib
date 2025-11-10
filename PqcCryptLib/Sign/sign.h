#ifndef _SIGN_H
#define _SIGN_H

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>

typedef enum {
	/** Used to indicate that some undefined error occurred. */
	OQS_ERROR = -1,
	/** Used to indicate successful return from function. */
	OQS_SUCCESS = 0,
	/** Used to indicate failures in external libraries (e.g., OpenSSL). */
	OQS_EXTERNAL_LIB_ERROR_OPENSSL = 50,
} OQS_STATUS;


/**
 * Signature schemes object
 */
typedef struct OQS_SIG {

	/** Printable string representing the name of the signature scheme. */
	// CONST UINT8 *method_name;

	/**
	 * Printable string representing the version of the cryptographic algorithm.
	 *
	 * Implementations with the same method_name and same alg_version will be interoperable.
	 * See README.md for information about algorithm compatibility.
	 */
	// CONST UINT8 *alg_version;

	/** The NIST security level (1, 2, 3, 4, 5) claimed in this algorithm's original NIST submission. */
	UINT8 claimed_nist_level;

	/** Whether the signature offers EUF-CMA security (TRUE) or not (FALSE). */
	BOOLEAN euf_cma;

	/** Whether the signature offers SUF-CMA security (TRUE) or not (FALSE). */
	BOOLEAN suf_cma;

	/** Whether the signature supports signing with a context string (TRUE) or not (FALSE). */
	BOOLEAN sig_with_ctx_support;

	/** The length, in bytes, of public keys for this signature scheme. */
	UINTN length_public_key;
	/** The length, in bytes, of secret keys for this signature scheme. */
	UINTN length_secret_key;
	/** The (maximum) length, in bytes, of signatures for this signature scheme. */
	UINTN length_signature;

	/**
	 * Keypair generation algorithm.
	 *
	 * Caller is responsible for allocating sufficient memory for `public_key` and
	 * `secret_key`, based on the `length_*` members in this object or the per-scheme
	 * compile-time macros `OQS_SIG_*_length_*`.
	 *
	 * @param[out] public_key The public key represented as a byte string.
	 * @param[out] secret_key The secret key represented as a byte string.
	 * @return OQS_SUCCESS or OQS_ERROR
	 */
	OQS_STATUS (*keypair)(UINT8 *public_key, UINT8 *secret_key);

	/**
	 * Signature generation algorithm.
	 *
	 * Caller is responsible for allocating sufficient memory for `signature`,
	 * based on the `length_*` members in this object or the per-scheme
	 * compile-time macros `OQS_SIG_*_length_*`.
	 *
	 * @param[out] signature The signature on the message represented as a byte string.
	 * @param[out] signature_len The actual length of the signature. May be smaller than `length_signature` for some algorithms since some algorithms have variable length signatures.
	 * @param[in] message The message to sign represented as a byte string.
	 * @param[in] message_len The length of the message to sign.
	 * @param[in] secret_key The secret key represented as a byte string.
	 * @return OQS_SUCCESS or OQS_ERROR
	 */
	OQS_STATUS (*sign)(
        UINT8 *signature, 
        UINTN *signature_len, 
        CONST UINT8 *message, 
        UINTN message_len, 
        CONST UINT8 *secret_key
    );

	/**
	 * Signature generation algorithm, with custom context string.
	 *
	 * Caller is responsible for allocating sufficient memory for `signature`,
	 * based on the `length_*` members in this object or the per-scheme
	 * compile-time macros `OQS_SIG_*_length_*`.
	 *
	 * @param[out] signature The signature on the message represented as a byte string.
	 * @param[out] signature_len The actual length of the signature. May be smaller than `length_signature` for some algorithms since some algorithms have variable length signatures.
	 * @param[in] message The message to sign represented as a byte string.
	 * @param[in] message_len The length of the message to sign.
	 * @param[in] ctx_str The context string used for the signature. This value can be set to NULL if a context string is not needed (i.e., for algorithms that do not support context strings or if an empty context string is used).
	 * @param[in] ctx_str_len The context string used for the signature. This value can be set to 0 if a context string is not needed (i.e., for algorithms that do not support context strings or if an empty context string is used).
	 * @param[in] secret_key The secret key represented as a byte string.
	 * @return OQS_SUCCESS or OQS_ERROR
	 */
	OQS_STATUS (*sign_with_ctx_str)(
        UINT8 *signature, 
        UINTN *signature_len, 
        CONST UINT8 *message, 
        UINTN message_len, 
        CONST UINT8 *ctx_str, 
        UINTN ctx_str_len, 
        CONST UINT8 *secret_key
    );

	/**
	 * Signature verification algorithm.
	 *
	 * @param[in] message The message represented as a byte string.
	 * @param[in] message_len The length of the message.
	 * @param[in] signature The signature on the message represented as a byte string.
	 * @param[in] signature_len The length of the signature.
	 * @param[in] public_key The public key represented as a byte string.
	 * @return OQS_SUCCESS or OQS_ERROR
	 */
	OQS_STATUS (*verify)(
        CONST UINT8 *message, 
        UINTN message_len, 
        CONST UINT8 *signature, 
        UINTN signature_len, 
        CONST UINT8 *public_key
    );

	/**
	 * Signature verification algorithm, with custom context string.
	 *
	 * @param[in] message The message represented as a byte string.
	 * @param[in] message_len The length of the message.
	 * @param[in] signature The signature on the message represented as a byte string.
	 * @param[in] signature_len The length of the signature.
	 * @param[in] ctx_str The context string for the signature. This value can be set to NULL if a context string is not needed (i.e., for algorithms that do not support context strings or if an empty context string is used).
	 * @param[in] ctx_str_len The length of the context string. This value can be set to 0 if a context string is not needed (i.e., for algorithms that do not support context strings or if an empty context string is used).
	 * @param[in] public_key The public key represented as a byte string.
	 * @return OQS_SUCCESS or OQS_ERROR
	 */
	OQS_STATUS (*verify_with_ctx_str)(
        CONST UINT8 *message, 
        UINTN message_len, 
        CONST UINT8 *signature, 
        UINTN signature_len, 
        CONST UINT8 *ctx_str, 
        UINTN ctx_str_len, 
        CONST UINT8 *public_key
    );


} OQS_SIG;

#endif //_SIGN_H
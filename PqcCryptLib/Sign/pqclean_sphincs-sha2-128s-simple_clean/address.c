#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>

#include "address.h"
#include "params.h"
#include "utils.h"

/*
 * Specify which level of Merkle tree (the "layer") we're working on
 */
EFIAPI 
VOID 
set_layer_addr(
    UINT32 addr[8], 
    UINT32 layer
) {
    ((UINT8 *)addr)[SPX_OFFSET_LAYER] = (UINT8)layer;
}

/*
 * Specify which Merkle tree within the level (the "tree address") we're working on
 */
EFIAPI 
VOID 
set_tree_addr(
    UINT32 addr[8], 
    UINT64 tree
) {
    ull_to_bytes(&((UINT8 *)addr)[SPX_OFFSET_TREE], 8, tree );
}

/*
 * Specify the reason we'll use this address structure for, that is, what
 * hash will we compute with it.  This is used so that unrelated types of
 * hashes don't accidentally get the same address structure.  The type will be
 * one of the SPX_ADDR_TYPE constants
 */
EFIAPI 
VOID 
set_type(
    UINT32 addr[8], 
    UINT32 type
) {
    ((UINT8 *)addr)[SPX_OFFSET_TYPE] = (UINT8)type;
}

/*
 * Copy the layer and tree fields of the address structure.  This is used
 * when we're doing multiple types of hashes within the same Merkle tree
 */
EFIAPI 
VOID 
copy_subtree_addr(
    UINT32 out[8], 
    CONST UINT32 in[8]
) {
    CopyMem( out, in, SPX_OFFSET_TREE + 8 );
}

/* These functions are used for OTS addresses. */

/*
 * Specify which Merkle leaf we're working on; that is, which OTS keypair
 * we're talking about.
 */
EFIAPI 
VOID 
set_keypair_addr(
    UINT32 addr[8], 
    UINT32 keypair
) {
    /* We have > 256 OTS at the bottom of the Merkle tree; to specify */
    /* which one, we'd need to express it in two bytes */
    ((UINT8 *)addr)[SPX_OFFSET_KP_ADDR2] = (UINT8)(keypair >> 8);
    ((UINT8 *)addr)[SPX_OFFSET_KP_ADDR1] = (UINT8)keypair;
}

/*
 * Copy the layer, tree and keypair fields of the address structure.  This is
 * used when we're doing multiple things within the same OTS keypair
 */
EFIAPI 
VOID 
copy_keypair_addr(
    UINT32 out[8], 
    CONST UINT32 in[8]
) {
    CopyMem( out, in, SPX_OFFSET_TREE + 8 );
    ((UINT8 *)out)[SPX_OFFSET_KP_ADDR2] = ((UINT8 *)in)[SPX_OFFSET_KP_ADDR2];
    ((UINT8 *)out)[SPX_OFFSET_KP_ADDR1] = ((UINT8 *)in)[SPX_OFFSET_KP_ADDR1];
}

/*
 * Specify which Merkle chain within the OTS we're working with
 * (the chain address)
 */
EFIAPI 
VOID 
set_chain_addr(
    UINT32 addr[8], 
    UINT32 chain
) {
    ((UINT8 *)addr)[SPX_OFFSET_CHAIN_ADDR] = (UINT8)chain;
}

/*
 * Specify where in the Merkle chain we are
* (the hash address)
 */
EFIAPI 
VOID 
set_hash_addr(
    UINT32 addr[8], 
    UINT32 hash
) {
    ((UINT8 *)addr)[SPX_OFFSET_HASH_ADDR] = (UINT8)hash;
}

/* These functions are used for all hash tree addresses (including FORS). */

/*
 * Specify the height of the node in the Merkle/FORS tree we are in
 * (the tree height)
 */
EFIAPI 
VOID 
set_tree_height(
    UINT32 addr[8], 
    UINT32 tree_height
) {
    ((UINT8 *)addr)[SPX_OFFSET_TREE_HGT] = (UINT8)tree_height;
}

/*
 * Specify the distance from the left edge of the node in the Merkle/FORS tree
 * (the tree index)
 */
EFIAPI 
VOID 
set_tree_index(
    UINT32 addr[8], 
    UINT32 tree_index
) {
    u32_to_bytes(&((UINT8 *)addr)[SPX_OFFSET_TREE_INDEX], tree_index );
}

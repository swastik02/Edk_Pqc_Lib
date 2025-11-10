#ifndef SPX_ADDRESS_H
#define SPX_ADDRESS_H

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>

#include "params.h"

/* The hash types that are passed to set_type */
#define SPX_ADDR_TYPE_WOTS 0
#define SPX_ADDR_TYPE_WOTSPK 1
#define SPX_ADDR_TYPE_HASHTREE 2
#define SPX_ADDR_TYPE_FORSTREE 3
#define SPX_ADDR_TYPE_FORSPK 4
#define SPX_ADDR_TYPE_WOTSPRF 5
#define SPX_ADDR_TYPE_FORSPRF 6

/*
 * Specify which level of Merkle tree (the "layer") we're working on
 */
EFIAPI 
VOID 
set_layer_addr(
    UINT32 addr[8], 
    UINT32 layer
);

/*
 * Specify which Merkle tree within the level (the "tree address") we're working on
 */
EFIAPI 
VOID 
set_tree_addr(
    UINT32 addr[8], 
    UINT64 tree
);

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
);

/*
 * Copy the layer and tree fields of the address structure.  This is used
 * when we're doing multiple types of hashes within the same Merkle tree
 */
EFIAPI 
VOID 
copy_subtree_addr(
    UINT32 out[8], 
    CONST UINT32 in[8]
);

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
);

/*
 * Copy the layer, tree and keypair fields of the address structure.  This is
 * used when we're doing multiple things within the same OTS keypair
 */
EFIAPI 
VOID 
copy_keypair_addr(
    UINT32 out[8], 
    CONST UINT32 in[8]
);

/*
 * Specify which Merkle chain within the OTS we're working with
 * (the chain address)
 */
EFIAPI 
VOID 
set_chain_addr(
    UINT32 addr[8], 
    UINT32 chain
);

/*
 * Specify where in the Merkle chain we are
* (the hash address)
 */
EFIAPI 
VOID 
set_hash_addr(
    UINT32 addr[8], 
    UINT32 hash
);
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
);
/*
 * Specify the distance from the left edge of the node in the Merkle/FORS tree
 * (the tree index)
 */
EFIAPI 
VOID 
set_tree_index(
    UINT32 addr[8], 
    UINT32 tree_index
);
#endif

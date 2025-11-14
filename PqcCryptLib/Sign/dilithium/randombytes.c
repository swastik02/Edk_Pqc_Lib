
#include "randombytes.h"


VOID
EFIAPI
randombytes(
    UINT8 *out,
    UINTN outlen
){
  BOOLEAN ret;

  while(outlen > 0) {

    ret = GetRandomNumber32((UINT32*)out);

    if (ret == TRUE) {
      out += sizeof(UINT32);
      outlen -= sizeof(UINT32);
    }
    else {
      return;
    }
  }
}



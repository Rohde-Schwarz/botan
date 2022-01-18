#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "dilithium_params.h"

void ntt(int32_t a[N]);

void invntt_tomont(int32_t a[N]);

#endif

#ifndef FPR_RANDOM_H
#define FPR_RANDOM_H


#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

struct fpr_random {
	mbedtls_entropy_context		entropy;
	mbedtls_ctr_drbg_context	ctr_drbg;
};


int fpr_random_init(struct fpr_random *random, const char *custom);
void fpr_random_deinit(struct fpr_random *random);
void fpr_random_bytes(void *bytes, size_t len);
uint32_t fpr_random_uint32(uint32_t min, uint32_t max);

#endif

#ifndef FPR_SHA256_H
#define FPR_SHA256_H

#include <stdint.h>

#include <mbedtls/sha256.h>

#define FPR_SHA256_LEN 32

struct fpr_sha256 {
	mbedtls_sha256_context ctx;
};

void  fpr_sha256_init(struct fpr_sha256 *sha256);
void  fpr_sha256_free(struct fpr_sha256 *sha256);

/* The digest updating function */
void  fpr_sha256_update(struct fpr_sha256 *sha256, void *data, size_t len);

/* This generates the final digest. NOTE: digest array must be at
 * least FPR_SHA256_LEN bytes */
void  fpr_sha256_finish(struct fpr_sha256 *sha256, uint8_t *digest);

/* Fast hashing function that requires no ctx */
void  fpr_sha256(void *data, size_t len, uint8_t *digest);


#endif

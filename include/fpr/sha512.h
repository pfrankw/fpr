#ifndef FPR_SHA512_H
#define FPR_SHA512_H

#include <stdint.h>

#include <mbedtls/sha512.h>


#define FPR_SHA512_LEN 64

struct fpr_sha512 {
	mbedtls_sha512_context ctx;
};

void  fpr_sha512_init(struct fpr_sha512 *sha512);
void  fpr_sha512_free(struct fpr_sha512 *sha512);

/* The digest updating function */
void  fpr_sha512_update(struct fpr_sha512 *sha512, void *data, size_t len);

/*
 * This generates the final digest.
 * NOTE: digest array must be at least FPR_SHA512_LEN bytes
 */
void  fpr_sha512_finish(struct fpr_sha512 *sha512, uint8_t *digest);

/* Fast hashing function that requires no ctx */
void  fpr_sha512(void *data, size_t len, uint8_t *digest);

#endif

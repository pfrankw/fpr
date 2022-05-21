#ifndef FPR_SHA1_H
#define FPR_SHA1_H

#include <stdint.h>

#include <mbedtls/sha1.h>

#define FPR_SHA1_LEN 20

struct fpr_sha1 {
	mbedtls_sha1_context ctx;
};

void  fpr_sha1_init(struct fpr_sha1 *sha1);
void  fpr_sha1_free(struct fpr_sha1 *sha1);

/* The digest updating function */
void  fpr_sha1_update(struct fpr_sha1 *sha1, void *data, size_t len);

/*
 * This generates the final digest.
 * NOTE: digest array must be at least FPR_SHA1_LEN bytes
 */
void  fpr_sha1_finish(struct fpr_sha1 *sha1, uint8_t *digest);

/* Fast hashing function that requires no ctx */
void  fpr_sha1(void *data, size_t len, uint8_t *digest);


#endif

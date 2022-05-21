#include "fpr/sha1.h"


void fpr_sha1_init(struct fpr_sha1 *sha1)
{
	mbedtls_sha1_init(&sha1->ctx);
}

void fpr_sha1_free(struct fpr_sha1 *sha1)
{
	mbedtls_sha1_free(&sha1->ctx);
}

void fpr_sha1_update(struct fpr_sha1 *sha1, void *data, size_t len)
{
	mbedtls_sha1_update(&sha1->ctx, data, len);
}

void fpr_sha1_finish(struct fpr_sha1 *sha1, uint8_t *digest)
{
	mbedtls_sha1_finish(&sha1->ctx, digest);
}

void fpr_sha1(void *data, size_t len, uint8_t *digest)
{
	mbedtls_sha1(data, len, digest);
}

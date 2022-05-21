#include "fpr/sha256.h"


void fpr_sha256_init(struct fpr_sha256 *sha256)
{
	mbedtls_sha256_init(&sha256->ctx);
}

void fpr_sha256_free(struct fpr_sha256 *sha256)
{
	mbedtls_sha256_free(&sha256->ctx);
}

void fpr_sha256_update(struct fpr_sha256 *sha256, void *data, size_t len)
{
	mbedtls_sha256_update(&sha256->ctx, data, len);
}

void fpr_sha256_finish(struct fpr_sha256 *sha256, uint8_t *digest)
{
	mbedtls_sha256_finish(&sha256->ctx, digest);
}

void fpr_sha256(void *data, size_t len, uint8_t *digest)
{
	mbedtls_sha256(data, len, digest, 0);
}

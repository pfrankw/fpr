#include "fpr/sha512.h"


void fpr_sha512_init(struct fpr_sha512 *sha512)
{
	mbedtls_sha512_init(&sha512->ctx);
}

void fpr_sha512_free(struct fpr_sha512 *sha512)
{
	mbedtls_sha512_free(&sha512->ctx);
}

void fpr_sha512_update(struct fpr_sha512 *sha512, void *data, size_t len)
{
	mbedtls_sha512_update(&sha512->ctx, data, len);
}

void fpr_sha512_finish(struct fpr_sha512 *sha512, uint8_t *digest)
{
	mbedtls_sha512_finish(&sha512->ctx, digest);
}

void fpr_sha512(void *data, size_t len, uint8_t *digest)
{
	mbedtls_sha512(data, len, digest, 0);
}

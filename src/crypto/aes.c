#include <string.h>

#include "fpr/aes.h"


int fpr_aes_init(struct fpr_aes *aes, int bits, const uint8_t *key)
{
	if (!aes || !bits || bits % 128 != 0 || bits > 256 || !key)
		return -1;

	memset(aes, 0, sizeof(struct fpr_aes));
	mbedtls_aes_init(&aes->ctx);
	mbedtls_aes_setkey_enc(&aes->ctx, key, bits);

	return 0;
}

void fpr_aes_deinit(struct fpr_aes *aes)
{
	if (!aes)
		return;

	mbedtls_aes_free(&aes->ctx);
	memset(aes, 0, sizeof(struct fpr_aes));
}

void fpr_aes_crypt_ctr(struct fpr_aes *aes, void *input, void *output, size_t len)
{
	if (!aes || !input || !output || !len)
		return;

	mbedtls_aes_crypt_ctr(&aes->ctx, len, &aes->nc_off, aes->nonce_counter,
			      aes->stream_block, input, output);
}

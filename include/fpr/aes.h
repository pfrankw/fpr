#ifndef FPR_AES_H
#define FPR_AES_H

#include <stdint.h>

#include <mbedtls/aes.h>


struct fpr_aes {
	mbedtls_aes_context	ctx;
	size_t				nc_off;
	uint8_t				nonce_counter[16];
	uint8_t				stream_block[16];
};


int   fpr_aes_init(struct fpr_aes *aes, int bits, const uint8_t *key);
void  fpr_aes_deinit(struct fpr_aes *aes);
void  fpr_aes_crypt_ctr(struct fpr_aes *aes, void *input, void *output, size_t len);

#endif

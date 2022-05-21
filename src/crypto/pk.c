#include <string.h>
#include <stdlib.h>

#include "fpr/pk.h"
#include "fpr/sha256.h"

int fpr_pk_rsa_init_gen(struct fpr_pk *pk, int bits)
{
	int r = -1;

	if (!pk || bits % 1024 != 0 || bits > FPR_PK_RSA_MAX_KEY_LEN)
		goto cleanup;

	memset(pk, 0, sizeof(struct fpr_pk));

	if (fpr_random_init(&pk->random, 0))
		goto cleanup;

	mbedtls_pk_init(&pk->ctx);

	if (mbedtls_pk_setup(&pk->ctx,
			     mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0)
		goto cleanup;

	if (mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk->ctx),
				mbedtls_ctr_drbg_random, &pk->random.ctr_drbg, bits, 65537) != 0)
		goto cleanup;

	r = 0;
cleanup:
	if (r != 0) fpr_pk_deinit(pk);
	return r;
}

void fpr_pk_deinit(struct fpr_pk *pk)
{
	if (!pk)
		return;

	mbedtls_pk_free(&pk->ctx);
	fpr_random_deinit(&pk->random);
	memset(pk, 0, sizeof(struct fpr_pk));
}

int fpr_pk_init_pk(struct fpr_pk *pk, mbedtls_pk_context *mbed_pk, int pub)
{
	int r = -1;
	uint8_t *der = 0;
	size_t llen = 0;

	if (!pk || !mbed_pk)
		goto cleanup;

	der = (uint8_t *)malloc(2048); //FIXME

	/* ---- BEGIN HACK ---- */
	if ((llen = fpr_pk_to_der((struct fpr_pk *)mbed_pk, der, 2048, pub)) <= 0)
		goto cleanup;
	/* ---- END HACK ---- */

	if (fpr_pk_init_pemder(pk, der, llen, 1) != 0)
		goto cleanup;

	r = 0;
cleanup:
	if (r != 0) fpr_pk_deinit(pk);
	free(der);
	return r;
}

int fpr_pk_init_pemder(struct fpr_pk *pk, uint8_t *pem_or_der, size_t len, int pub)
{
	int r = -1;

	if (!pk || !pem_or_der || !len)
		goto cleanup;

	if (fpr_random_init(&pk->random, 0))
		goto cleanup;

	mbedtls_pk_init(&pk->ctx);

	if (pub) {
		if (mbedtls_pk_parse_public_key(&pk->ctx, pem_or_der, len) != 0)
			goto cleanup;
	} else {
		if (mbedtls_pk_parse_key(&pk->ctx, pem_or_der, len, 0, 0) != 0)
			goto cleanup;
	}

	r = 0;
cleanup:
	if (r != 0) fpr_pk_deinit(pk);
	return r;
}

int fpr_pk_to_der(struct fpr_pk *pk, uint8_t *der, size_t len, int pub)
{
	int llen;

	if (!pk || !der || !len)
		return 0;

	if (pub)
		llen = mbedtls_pk_write_pubkey_der(&pk->ctx, der, len);
	else
		llen = mbedtls_pk_write_key_der(&pk->ctx, der, len);

	memcpy(der, der + len - llen, llen);

	return llen;
}

int fpr_pk_to_pem(struct fpr_pk *pk, uint8_t *pem, size_t len, int pub)
{
	if (!pk || !pem || !len)
		return -1;

	if (pub) {
		if (mbedtls_pk_write_pubkey_pem(&pk->ctx, pem, len) != 0)
			return -1;
	} else {
		if (mbedtls_pk_write_key_pem(&pk->ctx, pem, len) != 0)
			return -1;
	}
	return 0;
}

int fpr_pk_pub_encrypt(struct fpr_pk *pk, uint8_t *input,
		       uint8_t *output, size_t *len)
{
	if (!pk || !input || !output || !len || !(*len))
		return -1;

	return mbedtls_pk_encrypt(&pk->ctx, input, *len, output, len,
				  mbedtls_pk_get_len(&pk->ctx), mbedtls_ctr_drbg_random,
				  &pk->random.ctr_drbg);
}

int fpr_pk_verify(struct fpr_pk *pk, uint8_t *msg_digest,
		  uint8_t *sig, size_t siglen)
{
	if (!pk || !msg_digest || !sig || !siglen)
		return -1;

	return mbedtls_pk_verify(&pk->ctx, MBEDTLS_MD_SHA256,
				 msg_digest, 0, sig, siglen);
}

int fpr_pk_verify_data(struct fpr_pk *pk, uint8_t *data,
		       size_t data_len, uint8_t *sig, size_t sig_len)
{
	unsigned char hash[32];

	if (!pk || !data || !data_len || !sig || !sig_len)
		return -1;

	fpr_sha256(data, data_len, hash);
	return fpr_pk_verify(pk, hash, sig, sig_len);
}

int fpr_pk_sign(struct fpr_pk *pk, uint8_t *hash, uint8_t *sig, size_t *sig_len)
{
	if (!pk || !hash || !sig || !sig_len)
		return -1;

	return mbedtls_pk_sign(&pk->ctx, MBEDTLS_MD_SHA256, hash, 0, sig, sig_len,
			       mbedtls_ctr_drbg_random, &pk->random.ctr_drbg);
}

int fpr_pk_sign_data(struct fpr_pk *pk, uint8_t *data,
		     size_t len, uint8_t *sig, size_t *sig_len)
{
	unsigned char hash[32];

	if (!pk || !data || !len || !sig || !sig_len)
		return -1;

	fpr_sha256(data, len, hash);
	return fpr_pk_sign(pk, hash, sig, sig_len);
}

int fpr_pk_hash(struct fpr_pk *pk, uint8_t *digest)
{
	uint8_t *derpk = 0;
	int len, r = -1;

	if (!pk || !digest)
		goto cleanup;

	derpk = (uint8_t *)malloc(2048); /* fixme */

	if ((len = fpr_pk_to_der(pk, derpk, 2048, 1)) <= 0)
		goto cleanup;

	fpr_sha256(derpk, len, digest);

	r = 0;
cleanup:
	free(derpk);
	return r;
}

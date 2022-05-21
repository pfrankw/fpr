#include <string.h>
#include <stdlib.h>

#include <mbedtls/bignum.h>

#include "fpr/pk.h"
#include "fpr/base64.h"
#include "fpr/sha256.h"

int fpr_pk_ecc_init_binary(struct fpr_pk *pk, fpr_ecc_group_id gid, uint8_t *key, size_t len, int pub)
{
	int r = -1;

	if (!pk || !key || !len)
		goto cleanup;

	memset(pk, 0, sizeof(struct fpr_pk));

	if (fpr_random_init(&pk->random, 0))
		goto cleanup;

	mbedtls_pk_init(&pk->ctx);

	if (mbedtls_pk_setup(&pk->ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0)
		goto cleanup;

	if (mbedtls_ecp_group_load(&(mbedtls_pk_ec(pk->ctx)->grp), gid) != 0)
		goto cleanup;

	if (pub) {
		uint8_t dec_key[(mbedtls_mpi_size(&(mbedtls_pk_ec(pk->ctx)->grp.P)) * 2) + 1];
		size_t olen = 0;

		if (key[0] == 0x02 || key[0] == 0x03) {
			if (mbedtls_ecp_decompress_pubkey(&(mbedtls_pk_ec(pk->ctx)->grp), key, len, dec_key, &olen, sizeof(dec_key)) != 0)
				goto cleanup;

			if (mbedtls_ecp_point_read_binary(&(mbedtls_pk_ec(pk->ctx)->grp), &(mbedtls_pk_ec(pk->ctx)->Q), dec_key, olen) != 0)
				goto cleanup;
		} else if (key[0] == 0x04) {
			if (mbedtls_ecp_point_read_binary(&(mbedtls_pk_ec(pk->ctx)->grp), &(mbedtls_pk_ec(pk->ctx)->Q), key, len) != 0)
				goto cleanup;
		} else { /* WTF */
			goto cleanup;
		}
	} else {
		if (mbedtls_mpi_read_binary(&(mbedtls_pk_ec(pk->ctx)->d), key, len) != 0)
			goto cleanup;

		if (mbedtls_ecp_mul(&(mbedtls_pk_ec(pk->ctx)->grp), &(mbedtls_pk_ec(pk->ctx)->Q), &(mbedtls_pk_ec(pk->ctx)->d), &(mbedtls_pk_ec(pk->ctx)->grp.G), NULL, NULL) != 0)
			goto cleanup;
	}

	r = 0;
cleanup:
	if (r != 0) fpr_pk_deinit(pk);
	return r;
}

int fpr_pk_ecc_init_base64(struct fpr_pk *pk, fpr_ecc_group_id gid, const char *key, int pub)
{
	int r = -1;
	uint8_t *binkey = 0;
	size_t binkey_len = 1024;

	binkey = malloc(binkey_len);

	if (fpr_base64_decode(key, binkey, &binkey_len) != 0)
		goto cleanup;

	r = fpr_pk_ecc_init_binary(pk, gid, binkey, binkey_len, pub);

cleanup:
	free(binkey);
	return r;
}

int fpr_pk_ecc_init_gen(struct fpr_pk *pk, fpr_ecc_group_id gid)
{
	int r = -1;

	if (!pk)
		goto cleanup;

	memset(pk, 0, sizeof(struct fpr_pk));

	if (fpr_random_init(&pk->random, 0))
		goto cleanup;

	mbedtls_pk_init(&pk->ctx);

	if (mbedtls_pk_setup(&pk->ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0)
		goto cleanup;

	if (mbedtls_ecp_gen_key(gid, mbedtls_pk_ec(pk->ctx), mbedtls_ctr_drbg_random, &pk->random.ctr_drbg) != 0)
		goto cleanup;

	r = 0;
cleanup:
	if (r != 0) fpr_pk_deinit(pk);
	return r;
}

int fpr_pk_ecc_to_binary(struct fpr_pk *pk, uint8_t *key, size_t len, int pub)
{
	int r = -1;
	size_t olen = 0;

	if (!pk || !key)
		goto cleanup;

	if (pub) {
		if (mbedtls_ecp_point_write_binary(&(mbedtls_pk_ec(pk->ctx)->grp), &(mbedtls_pk_ec(pk->ctx)->Q), MBEDTLS_ECP_PF_COMPRESSED, &olen, key, len) != 0)
			goto cleanup;
	} else {
		if (mbedtls_mpi_write_binary(&(mbedtls_pk_ec(pk->ctx)->d), key, len) != 0)
			goto cleanup;
	}

	r = 0;
cleanup:
	return r;
}

int fpr_pk_ecc_to_base64(struct fpr_pk *pk, char *key, size_t len, int pub)
{
	int r = -1;
	uint8_t *binkey = 0;
	size_t binkey_len;

	if (!pk || !key || !len)
		goto cleanup;

	binkey_len = mbedtls_pk_get_len(&pk->ctx) + (pub ? 1 : 0);
	binkey = malloc(binkey_len);

	if (fpr_pk_ecc_to_binary(pk, binkey, binkey_len, pub) != 0)
		goto cleanup;

	if (fpr_base64_encode(key, len, binkey, binkey_len) != 0)
		goto cleanup;

	r = 0;
cleanup:
	free(binkey);
	return r;
}

/*
 *  Decompresses an EC Public Key
 */
int mbedtls_ecp_decompress_pubkey(const mbedtls_ecp_group *grp,
				  const unsigned char *input, size_t ilen, unsigned char *output,
				  size_t *olen, size_t osize)
{
	int ret;
	mbedtls_mpi x, x3, ax, z, zexp, y;
	mbedtls_mpi_uint r;
	size_t plen;

	plen = mbedtls_mpi_size(&grp->P);
	*olen = 2 * plen + 1;

	if (ilen != plen + 1 || input[0] == 0x04)
		return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

	if (osize < 1)
		return 0;

	if (osize < *olen)
		return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;

	mbedtls_mpi_init(&x);
	mbedtls_mpi_init(&x3);
	mbedtls_mpi_init(&ax);
	mbedtls_mpi_init(&z);
	mbedtls_mpi_init(&zexp);
	mbedtls_mpi_init(&y);


	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&x, input + 1, ilen - 1));      // X point of the pubkey
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&x3, &x, &x));                      // X^2
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&x3, &x3, &x));                     // X^3
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&ax, &grp->A, &x));                 // AX
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&z, &x3, &ax));                     // X^3 + AX
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&z, &z, &grp->B));                  // X^3 + AX + B
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&zexp, &grp->P));                      // Z exponent
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&zexp, &zexp, 1));                  // Z exponent + 1
	MBEDTLS_MPI_CHK(mbedtls_mpi_div_int(&zexp, 0, &zexp, 4));               // Z exponent / 4
	MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&y, &z, &zexp, &grp->P, 0));        // Z^Zexp % P
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_int(&r, &y, 2));                        // To check if y is odd
	if (r != (input[0] - 2))
		MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&y, &grp->P, &y));

	output[0] = 0x04;                                                               // Uncompressed format
	memcpy(output + 1, input + 1, ilen - 1);                                        //0x04 + X
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&y, (output + 1 + ilen - 1), plen));   // 0x04 + X + Y

cleanup:
	mbedtls_mpi_free(&x);
	mbedtls_mpi_free(&x3);
	mbedtls_mpi_free(&ax);
	mbedtls_mpi_free(&z);
	mbedtls_mpi_free(&zexp);
	mbedtls_mpi_free(&y);


	return ret;
}

#include <stdlib.h>
#include <string.h>

#include "fpr/x509.h"
#include <fpr/sha256.h>

int fpr_x509_init_pk(struct fpr_x509 *x509, struct fpr_pk *pk,
	const char *cn, const char *org, const char *cc)
{
	int rr = 0, r = -1;
	mbedtls_x509write_cert write_cert;
	mbedtls_mpi serial;
	uint8_t *derbuf = 0;
	size_t derbuf_len = 8192;
	char subject_name[100];

	if (!x509 || !pk)
		goto cleanup;

	mbedtls_x509_crt_init(&x509->crt);
	mbedtls_x509write_crt_init(&write_cert);
	mbedtls_x509write_crt_set_md_alg(&write_cert, MBEDTLS_MD_SHA256);
	mbedtls_mpi_init(&serial);

	if (mbedtls_mpi_read_string(&serial, 10, "1") != 0)
		goto cleanup;

	mbedtls_x509write_crt_set_subject_key(&write_cert, &pk->ctx);
	mbedtls_x509write_crt_set_issuer_key(&write_cert, &pk->ctx);

	snprintf(subject_name, sizeof(subject_name),
		FPR_X509_SUBJECT_NAME_TEMPLATE, cn, org, cc);

	if (mbedtls_x509write_crt_set_subject_name(&write_cert, subject_name) != 0)
		goto cleanup;

	if (mbedtls_x509write_crt_set_issuer_name(&write_cert, subject_name) != 0)
		goto cleanup;

	if (mbedtls_x509write_crt_set_serial(&write_cert, &serial) != 0)
		goto cleanup;

	if (mbedtls_x509write_crt_set_validity(&write_cert,
			"19700101000000", "20380119031407") != 0)
		goto cleanup;

	if (mbedtls_x509write_crt_set_basic_constraints(&write_cert, 0, -1) != 0)
		goto cleanup;

	if (mbedtls_x509write_crt_set_subject_key_identifier(&write_cert) != 0)
		goto cleanup;

	if (mbedtls_x509write_crt_set_authority_key_identifier(&write_cert) != 0)
		goto cleanup;

	derbuf = (uint8_t *)malloc(derbuf_len);
	if ((rr = mbedtls_x509write_crt_der(&write_cert,
			derbuf, derbuf_len, 0, 0)) <= 0)
		goto cleanup;

	if (mbedtls_x509_crt_parse(&x509->crt, derbuf + (derbuf_len - rr), rr) != 0)
		goto cleanup;

	r = 0;
cleanup:
	free(derbuf);
	mbedtls_mpi_free(&serial);
	mbedtls_x509write_crt_free(&write_cert);
	return r;
}

void fpr_x509_deinit(struct fpr_x509 *x509)
{
	if (!x509)
		return;

	mbedtls_x509_crt_free(&x509->crt);
	memset(x509, 0, sizeof(struct fpr_x509));
}

int fpr_x509_init_der(struct fpr_x509 *x509, uint8_t *dercrt, size_t len)
{
	if (!x509 || !dercrt || !len)
		return -1;

	mbedtls_x509_crt_init(&x509->crt);

	if (mbedtls_x509_crt_parse_der(&x509->crt, dercrt, len) != 0)
		return -1;
	return 0;
}

int fpr_x509_init_x509(struct fpr_x509 *x509, const mbedtls_x509_crt *crt)
{
	if (!x509 || !crt)
		return -1;

	fpr_x509_init_der(x509, crt->raw.p, crt->raw.len);

	return 0;
}

int fpr_x509_get_pk_pubkey(struct fpr_x509 *x509, struct fpr_pk *pk)
{
	if (!x509 || !pk)
		return -1;

	if (fpr_pk_init_pk(pk, &x509->crt.pk, 1) != 0)
		return -1;

	return 0;
}

int fpr_x509_to_der(struct fpr_x509 *x509, uint8_t *der, size_t *len)
{
	if (!x509 || !der || !len || !*len || *len < x509->crt.raw.len)
		return -1;

	memcpy(der, x509->crt.raw.p, x509->crt.raw.len);
	return 0;
}

int fpr_x509_hash(struct fpr_x509 *x509, uint8_t *hash)
{
	if (!x509 || !hash || !x509->crt.raw.p || !x509->crt.raw.len)
		return -1;

	fpr_sha256(x509->crt.raw.p, x509->crt.raw.len, hash);

	return 0;
}

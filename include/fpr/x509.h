#ifndef FPR_X509_H
#define FPR_X509_H

#include <mbedtls/x509_crt.h>

#include <fpr/pk.h>

#define FPR_X509_HASH_LEN 32
#define FPR_X509_SUBJECT_NAME_TEMPLATE "CN=%s,O=%s,C=%s"

struct fpr_x509 {
	mbedtls_x509_crt crt;
};

int   fpr_x509_init_pk(struct fpr_x509 *x509, struct fpr_pk *pk, const char *cn, const char *org, const char *cc);
int   fpr_x509_init_x509(struct fpr_x509 *x509, const mbedtls_x509_crt *crt);
int   fpr_x509_init_der(struct fpr_x509 *x509, uint8_t *dercrt, size_t len);
void  fpr_x509_deinit(struct fpr_x509 *x509);

int   fpr_x509_get_pk_pubkey(struct fpr_x509 *x509, struct fpr_pk *pk);
int   fpr_x509_to_der(struct fpr_x509 *x509, uint8_t *der, size_t *len);
int   fpr_x509_hash(struct fpr_x509 *x509, uint8_t *hash);

#endif

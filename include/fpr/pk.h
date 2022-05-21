#ifndef FPR_PK_H
#define FPR_PK_H

#include <mbedtls/pk.h>
#include <fpr/random.h>

#define FPR_PK_RSA_MAX_KEY_LEN 8192
#define FPR_PK_RSA_HASH_LEN 32

#define fpr_ecc_group_id mbedtls_ecp_group_id

struct fpr_pk {
	mbedtls_pk_context	ctx;
	struct fpr_random	random;
};

/* BEGIN ECC related functions */
int   fpr_pk_ecc_init_binary(struct fpr_pk *pk, fpr_ecc_group_id gid, uint8_t *key, size_t len, int pub);

int   fpr_pk_ecc_init_base64(struct fpr_pk *pk, fpr_ecc_group_id gid, const char *key, int pub);

int   fpr_pk_ecc_init_gen(struct fpr_pk *pk, fpr_ecc_group_id gid);
/* END ECC related functions */

int   fpr_pk_rsa_init_gen(struct fpr_pk *pk, int bits);

int   fpr_pk_init_pk(struct fpr_pk *pk, mbedtls_pk_context *mbed_pk, int pub);

int   fpr_pk_init_pemder(struct fpr_pk *pk, uint8_t *pem_or_der, size_t len, int pub);

void  fpr_pk_deinit(struct fpr_pk *pk);

int   fpr_pk_to_der(struct fpr_pk *pk, uint8_t *der, size_t len, int pub);
int   fpr_pk_to_pem(struct fpr_pk *pk, uint8_t *pem, size_t len, int pub);

/* BEGIN ECC related functions */
int   fpr_pk_ecc_to_binary(struct fpr_pk *pk, uint8_t *key, size_t len, int pub);
int   fpr_pk_ecc_to_base64(struct fpr_pk *pk, char *key, size_t len, int pub);
/* END ECC related functions */

int   fpr_pk_pub_encrypt(struct fpr_pk *pk, uint8_t *input, uint8_t *output, size_t *len);

int   fpr_pk_verify(struct fpr_pk *pk, uint8_t *msg_digest, uint8_t *sig, size_t siglen);
int   fpr_pk_verify_data(struct fpr_pk *pk, uint8_t *data, size_t data_len, uint8_t *sig, size_t sig_len);

int   fpr_pk_sign(struct fpr_pk *pk, uint8_t *hash, uint8_t *sig, size_t *sig_len);
int   fpr_pk_sign_data(struct fpr_pk *pk, uint8_t *data, size_t len, uint8_t *sig, size_t *sig_len);

int   fpr_pk_hash(struct fpr_pk *pk, uint8_t *digest);

int   mbedtls_ecp_decompress_pubkey(const mbedtls_ecp_group *grp, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize);

#endif

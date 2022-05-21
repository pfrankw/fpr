#ifndef FPR_SSL_H
#define FPR_SSL_H

#include <mbedtls/ssl.h>
#include <mbedtls/net.h>

#include <fpr/random.h>
#include <fpr/x509.h>

struct fpr_ssl {
	mbedtls_ssl_context	ssl;
	mbedtls_ssl_config	config;
	mbedtls_net_context	net;
	struct fpr_random		random;
	struct fpr_pk *		pk;
	struct fpr_pk		remote_pk;
	struct fpr_x509		remote_crt;
	struct fpr_x509		local_crt;
};

int   fpr_ssl_init(struct fpr_ssl *ssl, int fd, uint32_t read_msec_timeout, struct fpr_pk *pk, const char *cn, const char *org, const char *cc);
void  fpr_ssl_deinit(struct fpr_ssl *ssl);

int   fpr_ssl_write(struct fpr_ssl *ssl, void *buf, size_t len);
int   fpr_ssl_read(struct fpr_ssl *ssl, void *buf, size_t len);


#endif

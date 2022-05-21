#include <stdio.h>
#include <fpr/ssl.h>

#define SSL_DOMAIN "www.google.com"
#define SSL_PORT "443"

int main()
{
	int r = -1, rr = 0;
	mbedtls_net_context net = { 0 };
	struct fpr_ssl ssl;
	char buffer[1024];

	if (mbedtls_net_connect(&net, SSL_DOMAIN, SSL_PORT, MBEDTLS_NET_PROTO_TCP) != 0)
		goto exit;

	if (fpr_ssl_init(&ssl, net.fd, 0, 0, 0, 0, 0) != 0)
		goto exit;

	if (fpr_ssl_write(&ssl, "GET / HTTP/1.1\r\n\r\n", 18) != 18)
		goto exit;

	while ((rr = fpr_ssl_read(&ssl, buffer, 1024)) == MBEDTLS_ERR_SSL_WANT_READ)
		mbedtls_net_usleep(50 * 1000);

	if (rr <= 0)
		goto exit;

	buffer[rr] = 0;
	printf("%s", buffer);

	r = 0;
exit:

	fpr_ssl_deinit(&ssl);
	mbedtls_net_free(&net);
	return r;
}

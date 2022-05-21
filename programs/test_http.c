#include <stdio.h>
#include <string.h>

#include <uthash.h>

#include <fpr/http.h>

int main()
{
	fpr_http *res = 0;
	struct fpr_http_header *cur, *tmp;
	char *http_res = "HTTP/1.0 200 OK\r\n"
			"Connection: close\r\n"
			"Server: Apache\r\n"
			"\r\n";

	res = fpr_http_new();

	fpr_http_putbuf(res, (unsigned char *)http_res, strlen(http_res));

	printf("\nHEADERS:\n");
	HASH_ITER (hh, res->headers, cur, tmp) {
		printf("%s: %s\n", cur->name, cur->value);
	}
	fpr_http_free(res);
}

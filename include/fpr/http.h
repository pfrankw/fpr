#ifndef FPR_HTTP_H
#define FPR_HTTP_H

#include <uthash.h>

#include <fpr/fsm.h>

#define FPR_HTTP_BUF_LEN 1024

typedef void (*htt_body_cb)(unsigned char *data, size_t len, void *arg);

struct fpr_http_header {
	char *name;
	char *value;

	UT_hash_handle hh;
};

typedef struct {
	int				majver;
	int				minver;
	int				status;

	struct fpr_fsm	fsm;
	unsigned char	buf[FPR_HTTP_BUF_LEN];
	size_t			bi;

	struct fpr_http_header *headers;
} fpr_http;


fpr_http* fpr_http_new();
void fpr_http_free(fpr_http *http);
void fpr_http_set_on_body(fpr_http *http, htt_body_cb cb, void *arg);

int fpr_http_putbyte(fpr_http *http, unsigned char byte);
int fpr_http_putbuf(fpr_http *http, unsigned char *buf, size_t len);


#endif

#ifndef FPR_STREAM_H
#define FPR_STREAM_H

#include <sys/types.h>
#include <stdint.h>

enum {
	FPR_STREAM_READABLE = 0,
	FPR_STREAM_WRITABLE
};

struct fpr_stream;

struct fpr_streamops {
	int (*init)(struct fpr_stream*, void *param);
	ssize_t (*read)(struct fpr_stream*, unsigned char*, size_t);
	ssize_t (*write)(struct fpr_stream*, const unsigned char*, size_t);
	void (*close)(struct fpr_stream*);
};

struct fpr_stream_listener {
	int ev;
	void *p;
	void (*onev)(struct fpr_stream*, int ev, void *p);
	struct fpr_stream_listener *next;
};

struct fpr_stream {
	const struct fpr_streamops *ops;
	void *priv;
	struct fpr_stream_listener *listeners;
};

struct fpr_stream* fpr_stream_new(struct fpr_streamops *ops, void *param);
void fpr_stream_close(struct fpr_stream *stream);

static inline ssize_t fpr_stream_write(struct fpr_stream *stm, const unsigned char *buf, size_t len)
{
	return stm->ops->write(stm, buf, len);
}

static inline ssize_t fpr_stream_read(struct fpr_stream *stm, unsigned char *buf, size_t len)
{
	return stm->ops->read(stm, buf, len);
}

void fpr_stream_subscribe(struct fpr_stream *stm, void (*onev)(struct fpr_stream*, int, void*), int ev, void *p);

void _fpr_stream_emit(struct fpr_stream *stm, int ev);


#endif

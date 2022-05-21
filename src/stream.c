/*
 * stream.c
 *
 *  Created on: 17 ott 2017
 *      Author: francesco
 */

#include <stdlib.h>

#include <utlist.h>

#include <fpr/util.h>
#include <fpr/stream.h>

struct fpr_stream* fpr_stream_new(struct fpr_streamops *ops, void *param)
{
	struct fpr_stream *stm;

	AUTO_CALLOC(stm);
	stm->ops = ops;

	if (stm->ops->init) {
		if (stm->ops->init(stm, param) != 0)
			goto fail;
	}

	return stm;

fail:
	free(stm);
	return NULL;
}

void fpr_stream_close(struct fpr_stream *stm)
{
	if (!stm)
		return;

	if (stm->ops->close)
		stm->ops->close(stm);

	free(stm);
}

void fpr_stream_subscribe(struct fpr_stream *stm, void (*onev)(struct fpr_stream*, int, void*), int ev, void *p)
{
	struct fpr_stream_listener *lst;

	AUTO_CALLOC(lst);

	lst->onev = onev;
	lst->ev = ev;
	lst->p = p;

	LL_APPEND(stm->listeners, lst);
}

void _fpr_stream_emit(struct fpr_stream *stm, int ev)
{
	struct fpr_stream_listener *cur;

	LL_FOREACH (stm->listeners, cur) {
		if (cur->ev == ev) {
			cur->onev(stm, ev, cur->p);
		}
	}
}

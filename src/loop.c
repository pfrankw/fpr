#include <string.h>
#include <poll.h>

#include <utlist.h>

#include "fpr/util.h"
#include "fpr/loop.h"


static void io_free_all(fpr_loop *loop);
static void timer_free_all(fpr_loop *loop);


static fpr_loop *own_loop;

void fpr_loop_init_own()
{
	own_loop = fpr_loop_new();
}

void fpr_loop_free_own()
{
	fpr_loop_free(own_loop);
	own_loop = NULL;
}

fpr_loop* fpr_loop_new()
{
	fpr_loop *loop;

	AUTO_CALLOC(loop);
	return loop;
}

void fpr_loop_free(fpr_loop *loop)
{
	if (!loop)
		return;

	io_free_all(loop);
	timer_free_all(loop);

	free(loop);
}

static uint32_t calc_sleep(fpr_loop *loop)
{
	uint32_t msec = UINT32_MAX;
	struct fpr_timer *cur;

	DL_FOREACH (loop->timers, cur) {
		uint64_t total = cur->last_call + cur->interval;

		// This timer is already expired, must
		if (total < loop->clock) {
			return FPR_LOOP_MIN_SLEEP;
			// There is still some time
		} else if (total >= loop->clock) {
			uint64_t diff = total - loop->clock;

			if (diff < FPR_LOOP_MIN_SLEEP)
				return FPR_LOOP_MIN_SLEEP;
			else if (diff < msec)
				msec = diff;
		}
	}

	return msec;
}

static struct fpr_io *io_new(int fd, uint8_t ev, fpr_io_cb cb, void *arg)
{
	struct fpr_io *io;

	AUTO_CALLOC(io);

	io->fd = fd;
	io->ev = ev;
	io->cb = cb;
	io->arg = arg;

	return io;
}

static struct fpr_timer *timer_new(uint32_t interval, uint16_t flags,
			    fpr_timer_cb cb, void *arg)
{
	struct fpr_timer *timer;

	AUTO_CALLOC(timer);
	timer->last_call = fpr_clock();
	timer->interval = interval;
	timer->flags = flags;
	timer->cb = cb;
	timer->arg = arg;

	return timer;
}

static void io_free(struct fpr_io *io)
{
	if (!io)
		return;

	free(io);
}

static void timer_free(struct fpr_timer *timer)
{
	if (!timer)
		return;

	free(timer);
}

static void io_free_all(fpr_loop *loop)
{
	struct fpr_io *cur, *tmp;

	DL_FOREACH_SAFE (loop->io, cur, tmp) {
		DL_DELETE(loop->io, cur);
		io_free(cur);
	}
}

static void timer_free_all(fpr_loop *loop)
{
	struct fpr_timer *cur, *tmp;

	DL_FOREACH_SAFE (loop->timers, cur, tmp) {
		DL_DELETE(loop->timers, cur);
		timer_free(cur);
	}
}

struct fpr_io *fpr_loop_add_io(fpr_loop *loop, int fd,
			uint8_t ev, fpr_io_cb cb, void *arg)
{
	struct fpr_io *io = NULL;

	if (!loop) loop = own_loop;

	if (!cb)
		return NULL;

	io = io_new(fd, ev, cb, arg);

	DL_APPEND(loop->io, io);

	return io;
}

struct fpr_timer *fpr_loop_add_timer(fpr_loop *loop, uint32_t interval,
			      uint16_t flags, fpr_timer_cb cb, void *arg)
{
	struct fpr_timer *timer = NULL;

	if (!loop) loop = own_loop;

	if (!cb)
		return NULL;

	timer = timer_new(interval, flags, cb, arg);

	DL_APPEND(loop->timers, timer);

	return timer;
}

void fpr_loop_del_io(fpr_loop *loop, struct fpr_io *io)
{
	if (!loop) loop = own_loop;

	DL_DELETE(loop->io, io);
	io_free(io);
}

void fpr_loop_del_timer(fpr_loop *loop, struct fpr_timer *timer)
{
	if (!loop) loop = own_loop;

	DL_DELETE(loop->timers, timer);
	timer_free(timer);
}

static void timers_run(fpr_loop *loop)
{
	struct fpr_timer *cur, *tmp;

	DL_FOREACH_SAFE (loop->timers, cur, tmp) {

		if (cur->flags & FPR_TIMER_FLAG_DELETE) {
			fpr_loop_del_timer(loop, cur);
			continue;
		}

		if (loop->clock - cur->last_call >= cur->interval) {

			// Can't delete it now, because if it is deleted inside cur->cb then
			// there is a double free. So we schedule for next time.

			if (cur->flags & FPR_TIMER_FLAG_ONCE)
				cur->flags |= FPR_TIMER_FLAG_DELETE;


			cur->last_call = loop->clock;

			cur->cb(cur->arg);
		}
	}
}

static void set_pollfd_by_io(struct pollfd *pfd, struct fpr_io *io)
{
	pfd->fd = io->fd;

	if (io->ev & FPR_IO_EVREAD)
		pfd->events |= POLLIN;

	if (io->ev & FPR_IO_EVWRITE)
		pfd->events |= POLLOUT;
}

static uint8_t revents_to_rev(short revents)
{
	uint8_t rev = 0;

	if (revents & POLLIN)
		rev |= FPR_IO_EVREAD;

	if (revents & POLLOUT)
		rev |= FPR_IO_EVWRITE;

	if (revents & POLLERR)
		rev |= FPR_IO_EVERROR;

	return rev;
}

static void io_fire(struct fpr_io *io, uint8_t rev)
{
	io->cb(rev, io->arg);
}

static int io_poll(fpr_loop *loop)
{
	int r = -1, rp;
	struct pollfd *pfd = 0;
	struct fpr_io *cur, *tmp;
	size_t i = 0, n_io;

	DL_COUNT(loop->io, cur, n_io);

	pfd = calloc(n_io, sizeof(struct pollfd));

	DL_FOREACH (loop->io, cur) {
		set_pollfd_by_io(&pfd[i], cur);
		i++;
	}

	rp = poll(pfd, n_io, calc_sleep(loop));


	if (rp == 0)
		goto success_cleanup;
	else if (rp < 0)
		goto cleanup;


	i = 0;
	DL_FOREACH_SAFE (loop->io, cur, tmp) {
		struct fpr_io *io = cur;

		if (pfd[i].revents != 0) { // If there are revents
			uint8_t rev = revents_to_rev(pfd[i].revents);

			io_fire(io, rev);
			rp--;
			// rp is the counter of pollfd structures with revents set.
			// We can use rp as counter.
		}

		i++;
	}

success_cleanup:
	r = 0;
cleanup:
	free(pfd);
	return r;
}

void fpr_loop_run(fpr_loop *loop)
{
	if (!loop) loop = own_loop;

	loop->clock = fpr_clock();
	io_poll(loop);
	timers_run(loop);
}

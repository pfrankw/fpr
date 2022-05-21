#ifndef FPR_LOOP_H
#define FPR_LOOP_H


#include <stdint.h>

#include <fpr/clock.h>


#define FPR_LOOP_MIN_SLEEP 50

struct fpr_io;
struct fpr_timer;

typedef void (*fpr_timer_cb)(void *arg);
typedef void (*fpr_io_cb)(uint8_t rev, void *arg);


enum {
	FPR_TIMER_FLAG_ONCE = 1 << 0,
	FPR_TIMER_FLAG_DELETE = 1 << 1
};

enum {
	FPR_IO_EVREAD	= 1 << 0,
	FPR_IO_EVWRITE	= 1 << 1,
	FPR_IO_EVERROR	= 1 << 2
};

#define FPR_IO_EVALL (FPR_IO_EVREAD|FPR_IO_EVWRITE|FPR_IO_EVERROR)

struct fpr_timer {
	uint64_t last_call;	// Last time called.
	uint32_t interval;	// Interval for the trigger.
	uint16_t flags;		// Timer flags.
	fpr_timer_cb cb;	// Callback for events.
	void *arg;		// Callback argument.

	struct fpr_timer *prev, *next;
};

struct fpr_io {
	int			fd;     // File descriptor.
	uint8_t		ev;     // Events to be checked for.
	fpr_io_cb	cb;     // Callback for events.
	void *		arg;    // Callback argument.

	struct fpr_io *prev, *next;
};

typedef struct {
	uint64_t			clock;
	struct fpr_io		*io;
	struct fpr_timer	*timers;
} fpr_loop;


void fpr_loop_init_own();
void fpr_loop_free_own();

fpr_loop* fpr_loop_new();
void fpr_loop_free(fpr_loop *loop);

struct fpr_timer *fpr_loop_add_timer(fpr_loop *loop, uint32_t interval, uint16_t flags, fpr_timer_cb cb, void *arg);
void fpr_loop_del_timer(fpr_loop *loop, struct fpr_timer *timer);

struct fpr_io *fpr_loop_add_io(fpr_loop *loop, int fd, uint8_t ev, fpr_io_cb cb, void *arg);
void fpr_loop_del_io(fpr_loop *loop, struct fpr_io *io);

void fpr_loop_run(fpr_loop *loop);


#endif

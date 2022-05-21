#include <string.h>
#include <stdlib.h>

#include "fpr/util.h"
#include "fpr/fsm.h"
#include "fpr/http.h"

enum {
	STATE_HTTP = 0,
	STATE_MAJVER,
	STATE_MINVER,
	STATE_CODE,
	STATE_MSG,
	STATE_HNAME,
	STATE_HVALUE,
	STATE_END,
	STATE_ERROR,
	NSTATES
};

enum {
	EVENT_SLASH = 0,
	EVENT_SPACE,
	EVENT_DOT,
	EVENT_R,
	EVENT_N,
	EVENT_COLON,
	EVENT_STAR,
	NEVENTS
};

#define CURSTATE FPR_FSM_CURSTATE

struct statefn_data {
	fpr_http *http;
	char c;
};

static void writebuf(fpr_http *http, unsigned char byte)
{
	if (http->bi == FPR_HTTP_BUF_LEN - 1)
		return;

	http->buf[http->bi] = byte;
	http->bi++;
	http->buf[http->bi] = '\0';
}

static void	resetbuf(fpr_http *http)
{
	http->bi = 0;
}


static void dummy(int e, void *p){}

static void state_majver(int e, void *p)
{
	struct statefn_data *sd = p;

	sd->http->majver = sd->c - 48;
}

static void state_minver(int e, void *p)
{
	struct statefn_data *sd = p;

	sd->http->minver = sd->c - 48;
}

static void state_code(int e, void *p)
{
	struct statefn_data *sd = p;

	sd->http->status *= 10;
	sd->http->status += sd->c - 48;
}

static void state_msg(int e, void *p){}
static void state_hname(int e, void *p)
{
	struct statefn_data *sd = p;

	writebuf(sd->http, sd->c);
}

static void hname_to_hvalue(int e, void *p)
{
	struct statefn_data *sd = p;

	writebuf(sd->http, '\0');
}

static void state_hvalue(int e, void *p)
{
	struct statefn_data *sd = p;

	writebuf(sd->http, sd->c);
}

static void hvalue_to_hname(int e, void *p)
{
	struct statefn_data *sd = p;
	int hname_len;
	struct fpr_http_header *hdr;

	hname_len = strlen((const char*)sd->http->buf);
	if (sd->http->bi - hname_len < 2)
		goto cleanup;

	AUTO_CALLOC(hdr);

	hdr->name = strdup((char*)sd->http->buf);
	hdr->value = strdup((char*)sd->http->buf + hname_len + 1 + 1);

	HASH_ADD_KEYPTR(hh, sd->http->headers, hdr->name, strlen(hdr->name), hdr);

cleanup:
	resetbuf(sd->http);
}

static struct fpr_fsm_node fsm_table[NSTATES][NEVENTS] = {
		[STATE_HTTP] = {
				[EVENT_SLASH] = { .next = STATE_MAJVER, .fn = dummy }
		},
		[STATE_MAJVER] = {
				[EVENT_STAR] = { .next = CURSTATE, .fn = state_majver },
				[EVENT_DOT] = { .next = STATE_MINVER, .fn = dummy }
		},
		[STATE_MINVER] = {
				[EVENT_STAR] = { .next = CURSTATE, .fn = state_minver },
				[EVENT_SPACE] = { .next = STATE_CODE, .fn = dummy }
		},
		[STATE_CODE] = {
				[EVENT_STAR] = { .next = CURSTATE, .fn = state_code },
				[EVENT_SPACE] = { .next = STATE_MSG, .fn = dummy }
		},
		[STATE_MSG] = {
				[EVENT_SPACE] = { .next = CURSTATE, .fn = state_msg },
				[EVENT_STAR] = { .next = CURSTATE, .fn = state_msg },
				[EVENT_N] = { .next = STATE_HNAME, .fn = dummy }
		},
		[STATE_HNAME] = {
				[EVENT_COLON] = { .next = STATE_HVALUE, .fn = hname_to_hvalue },
				[EVENT_STAR] = { .next = CURSTATE, .fn = state_hname },
				[EVENT_N] = { .next = STATE_END, .fn = dummy }
		},
		[STATE_HVALUE] = {
				[EVENT_N] = { .next = STATE_HNAME, .fn = hvalue_to_hname },
				[EVENT_SLASH] = { .next = CURSTATE, .fn = state_hvalue },
				[EVENT_SPACE] = { .next = CURSTATE, .fn = state_hvalue },
				[EVENT_DOT] = { .next = CURSTATE, .fn = state_hvalue },
				[EVENT_COLON] = { .next = CURSTATE, .fn = state_hvalue },
				[EVENT_STAR] = { .next = CURSTATE, .fn = state_hvalue }
		}
};

static void setup_fsm(struct fpr_fsm *fsm)
{
	fsm->state = STATE_HTTP;
	fsm->nstates = NSTATES;
	fsm->nevents = NEVENTS;
	fsm->table = (struct fpr_fsm_node*) fsm_table;
}

fpr_http* fpr_http_new()
{
	fpr_http *http;

	AUTO_CALLOC(http);
	setup_fsm(&http->fsm);

	return http;
}

void fpr_http_free(fpr_http *http)
{
	struct fpr_http_header *cur, *tmp;

	if (!http)
		return;

	HASH_ITER (hh, http->headers, cur, tmp) {
		HASH_DEL(http->headers, cur);

		free(cur->name);
		free(cur->value);
		free(cur);
	}

	free(http);
}

static int chr_to_ev(char c)
{
	switch (c) {
	case '/': 	return EVENT_SLASH;
	case ' ': 	return EVENT_SPACE;
	case '.': 	return EVENT_DOT;
	case '\r':	return EVENT_R;
	case '\n':	return EVENT_N;
	case ':':	return EVENT_COLON;
	default:	return EVENT_STAR;
	}
}

int fpr_http_putbyte(fpr_http *http, unsigned char byte)
{

	struct statefn_data sd = {
			.http = http,
			.c = byte
	};

	//printf("%d\n", http->fsm.state);
	fpr_fsm_run(&http->fsm, chr_to_ev(byte), &sd);

	/*
	int r = -1;

	switch (http->state) {
	case STATE_STATUS:      r = state_status(http, byte); break;
	case STATE_HEADER:      r = state_header(http, byte); break;
	case STATE_BODY:        r = state_body(http, byte); break;

	case STATE_CHUNKED_POST_BODY:
		if (byte == '\n')
			change_state(http, STATE_CHUNKED_HEADER);
		r = 0;
		break;

	case STATE_CHUNKED_HEADER:
		r = state_ch_header(http, byte);
		break;

	case STATE_CHUNKED_END:
		if (byte == '\n')
			change_state(http, STATE_END);
		r = 0;
		break;

	default: break;
	}

	if (r != 0)
		change_state(http, STATE_ERROR);

	return r;*/
}

int fpr_http_putbuf(fpr_http *http, unsigned char *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (fpr_http_putbyte(http, buf[i]) != 0)
			return -1;

	return 0;
}

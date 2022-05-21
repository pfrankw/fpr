/*
 * test_fsm.c
 *
 *  Created on: 18 dic 2017
 *      Author: francesco
 */

#include <string.h>
#include <stdio.h>

#include <fpr/fsm.h>

static char *http_res = \
	"HTTP/1.1 200 OK\r\n" \
	"Server: Apache\r\n" \
	"Connection: close\r\n" \
	"Content-Encoding: gzip\r\n" \
	"\r\n";


enum {
	ST_HTTP = 0,
	ST_MAJVER,
	ST_MINVER,
	ST_CODE,
	ST_MSG,
	ST_HNAME,
	ST_HVAL,
	ST_END,
	NSTATES
};

enum {
	EV_SLASH = 0,
	EV_SPACE,
	EV_DOT,
	EV_R,
	EV_N,
	EV_COLON,
	EV_STAR,
	NEVENTS
};

#define CURSTATE FPR_FSM_CURSTATE

static void dummyfn(int e, void *p){
	printf("%c", (char)p);
}

static struct fpr_fsm_node fsm_table [NSTATES][NEVENTS] = {
		[ST_HTTP] = {
				[EV_SLASH] 	= { .next = ST_MAJVER, .fn = dummyfn }
		},
		[ST_MAJVER] = {
				[EV_STAR] 	= { .next = CURSTATE, .fn = dummyfn },
				[EV_DOT] 	= { .next = ST_MINVER, .fn = dummyfn }
		},
		[ST_MINVER] = {
				[EV_STAR] 	= { .next = CURSTATE, .fn = dummyfn },
				[EV_SPACE] 	= { .next = ST_CODE, .fn = dummyfn }
		},
		[ST_CODE] = {
				[EV_STAR] 	= { .next = CURSTATE, .fn = dummyfn },
				[EV_SPACE]	= { .next = ST_MSG, .fn = dummyfn }
		},
		[ST_MSG] = {
				[EV_STAR] 	= { .next = CURSTATE, .fn = dummyfn },
				[EV_SPACE] 	= { .next = CURSTATE, .fn = dummyfn },
				[EV_N]		= { .next = ST_HNAME, .fn = dummyfn }
		},
		[ST_HNAME] = {
				[EV_STAR]	= { .next = CURSTATE, .fn = dummyfn },
				[EV_COLON]	= { .next = ST_HVAL, .fn = dummyfn },
				[EV_N]		= { .next = ST_END, .fn = dummyfn }
		},
		[ST_HVAL] = {
				[EV_STAR]	= { .next = CURSTATE, .fn = dummyfn },
				[EV_N]		= { .next = ST_HNAME, .fn = dummyfn }
		}
};


int chr_to_ev(char c)
{
	switch (c) {
	case '/': 	return EV_SLASH;
	case ' ': 	return EV_SPACE;
	case '.': 	return EV_DOT;
	case '\r':	return EV_R;
	case '\n':	return EV_N;
	case ':':	return EV_COLON;
	default:	return EV_STAR;
	}
}


int main()
{

	int http_len = strlen(http_res);
	int i;

	struct fpr_fsm fsm = {
			.state = ST_HTTP,
			.nstates = NSTATES,
			.nevents = NEVENTS,
			.table = (struct fpr_fsm_node*) fsm_table
	};


	for (i=0; i<http_len; i++) {
		char c = http_res[i];
		size_t cc = c;

		//printf("STATE = %d\n", fsm.state);
		fpr_fsm_run(&fsm, chr_to_ev(c), (void*)cc);
	}

}

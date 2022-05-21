/*
 * fsm.h
 *
 *  Created on: 16 dic 2017
 *      Author: francesco
 */

#ifndef INCLUDE_FPR_FSM_H_
#define INCLUDE_FPR_FSM_H_

#include <stdint.h>

#define FPR_FSM_CURSTATE -1

struct fpr_fsm_node {
	int next;
	void (*fn)(int e, void *p);
};

struct fpr_fsm {

	// Current state
	int state;

	// FSM table
	uint32_t nstates;
	uint32_t nevents;
	struct fpr_fsm_node *table;
};


int fpr_fsm_run(struct fpr_fsm*, int e, void *p);

#endif /* INCLUDE_FPR_FSM_H_ */

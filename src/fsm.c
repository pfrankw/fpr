/*
 * fsm.c
 *
 *  Created on: 17 dic 2017
 *      Author: francesco
 */

#include <stdlib.h>

#include <fpr/fsm.h>


static struct fpr_fsm_node* get_node(struct fpr_fsm *fsm, int e)
{
	int index = (fsm->state * fsm->nevents) + e;
	return &(fsm->table[index]);
}

int fpr_fsm_run(struct fpr_fsm *fsm, int e, void *p)
{
	struct fpr_fsm_node *cur_node = NULL;

	cur_node = get_node(fsm, e);

	// If !fn the node is empty
	if (!cur_node->fn)
		return 0;

	cur_node->fn(e, p);

	// -1 means keep current state
	if (cur_node->next != FPR_FSM_CURSTATE)
		fsm->state = cur_node->next;


	return 0;
}

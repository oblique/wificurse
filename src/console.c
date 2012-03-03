/*
    wificurse - WiFi DoS tool
    Copyright (C) 2012  oblique

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dev.h"
#include "error.h"
#include "console.h"


void init_ap_list(struct ap_list *apl) {
	apl->head = NULL;
	apl->tail = NULL;
}

void free_ap_list(struct ap_list *apl) {
	struct access_point *tmp;

	while (apl->head != NULL) {
		tmp = apl->head;
		apl->head = apl->head->next;
		free(tmp);
	}

	apl->head = apl->tail = NULL;
}

int add_or_update_ap(struct ap_list *apl, uint8_t *bssid) {
	struct access_point *ap;

	ap = apl->head;
	while (ap != NULL) {
		if (memcmp(ap->bssid, bssid, sizeof(ap->bssid)) == 0)
			break;
		ap = ap->next;
	}

	if (ap == NULL) {
		ap = malloc(sizeof(*ap));
		if (ap == NULL)
			return_error("malloc");

		memset(ap, 0, sizeof(*ap));
		memcpy(ap->bssid, bssid, sizeof(ap->bssid));

		if (apl->head == NULL)
			apl->head = apl->tail = ap;
		else {
			ap->prev = apl->tail;
			apl->tail->next = ap;
			apl->tail = ap;
		}
	}

	ap->last_beacon_tm = time(NULL);
	ap->deauth = 1;
	ap->num_of_deauth++;

	return 0;
}

void clear_deauth(struct ap_list *apl) {
	struct access_point *ap;

	ap = apl->head;
	while (ap != NULL) {
		ap->deauth = 0;
		ap = ap->next;
	}
}

void unlink_ap(struct ap_list *apl, struct access_point *ap) {
	if (ap->prev)
		ap->prev->next = ap->next;
	else
		apl->head = ap->next;
	if (ap->next)
		ap->next->prev = ap->prev;
	else
		apl->tail = ap->prev;
}

void clear_scr() {
	printf("\033[2J\033[1;1H");
	fflush(stdout);
}

void update_scr(struct ap_list *apl, struct dev *dev) {
	struct access_point *ap, *tmp;

	/* move cursor at colum 1 row 1 */
	printf("\033[1;1H");

	printf("[ Channel: %3d ]\n\n", dev->chan);
	printf("Deauth  BSSID              Number of Deauth\n\n");

	ap = apl->head;
	while (ap != NULL) {
		if (time(NULL) - ap->last_beacon_tm >= 60) {
			tmp = ap;
			ap = ap->next;
			unlink_ap(apl, tmp);
			free(tmp);
			continue;
		}
		if (ap->deauth)
			printf(RED_COLOR("*"));
		else
			printf(" ");
		printf("       %02x:%02x:%02x:%02x:%02x:%02x", ap->bssid[0], ap->bssid[1],
		       ap->bssid[2], ap->bssid[3], ap->bssid[4], ap->bssid[5]);
		printf("  %d\n", ap->num_of_deauth);
		ap = ap->next;
	}

	/* clear screen from cursor to end of display */
	printf("\033[J");
	fflush(stdout);
}

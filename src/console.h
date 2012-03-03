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

#ifndef CONSOLE_H
#define CONSOLE_H

#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include "dev.h"


struct access_point {
	int deauth;
	unsigned int num_of_deauth;
	time_t last_beacon_tm;
	uint8_t bssid[IFHWADDRLEN];
	struct access_point *next;
	struct access_point *prev;
};

struct ap_list {
	struct access_point *head;
	struct access_point *tail;
};


void init_ap_list(struct ap_list *apl);
int add_or_update_ap(struct ap_list *apl, uint8_t *bssid);
void unlink_ap(struct ap_list *apl, struct access_point *ap);
void clear_deauth(struct ap_list *apl);
void clear_scr();
void update_scr(struct ap_list *apl, struct dev *dev);

#define RED_COLOR(str) "\033[1;31m" str "\033[0m"

#endif

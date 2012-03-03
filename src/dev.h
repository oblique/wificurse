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

#ifndef DEV_H
#define DEV_H

#include <sys/socket.h>
#include <linux/wireless.h>


struct dev {
	char ifname[IFNAMSIZ+1];
	int ifindex;
	int fd;
	int chan;
	struct ifreq old_flags;
	struct iwreq old_mode;
};


void init_dev(struct dev *dev);

#endif

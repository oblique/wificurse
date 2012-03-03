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

#ifndef IW_H
#define IW_H

#include <stdint.h>
#include "dev.h"


struct radiotap_hdr {
	uint8_t  version;
	uint8_t  pad;
	uint16_t len;
	uint32_t present;
} __attribute__((__packed__));

struct write_radiotap_data {
	uint8_t  rate;
	uint8_t  pad;
	uint16_t tx_flags;
} __attribute__((__packed__));

#define RADIOTAP_F_PRESENT_RATE	(1<<2)
#define RADIOTAP_F_PRESENT_TX_FLAGS	(1<<15)
#define RADIOTAP_F_TX_FLAGS_NOACK	0x0008
#define RADIOTAP_F_TX_FLAGS_NOSEQ	0x0010


int iw_open(struct dev *dev);
void iw_close(struct dev *dev);
ssize_t iw_write(int fd, void *buf, size_t count);
ssize_t iw_read(int fd, void *buf, size_t count, uint8_t **pkt, size_t *pkt_sz);
int iw_can_change_channel(struct dev *dev);
int iw_set_channel(struct dev *dev, int chan);

#endif

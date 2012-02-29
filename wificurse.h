/*
    wificurse - WiFi DoS tool
    Copyright (C) <2012>  <oblique>

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

#ifndef WIFICURSE_H
#define WIFICURSE_H

#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/if.h>


struct dev {
	char ifname[IFNAMSIZ+1];
	int ifindex;
	int fd;
	int chan;
	struct ifreq old_flags;
	struct iwreq old_mode;
};


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

struct frame_control {
	uint8_t protocol_version:2;
	uint8_t type:2;
	uint8_t subtype:4;
	uint8_t to_ds:1;
	uint8_t from_ds:1;
	uint8_t more_frag:1;
	uint8_t retry:1;
	uint8_t pwr_mgt:1;
	uint8_t more_data:1;
	uint8_t protected_frame:1;
	uint8_t order:1;
} __attribute__((__packed__));

#define FRAME_CONTROL_SUBTYPE_DEAUTH	12
#define FRAME_CONTROL_SUBTYPE_BEACON	8

struct sequence_control {
	uint16_t fragment:4;
	uint16_t sequence:12;
} __attribute__((__packed__));

struct mgmt_frame {
	struct frame_control fc;
	uint16_t duration;
	uint8_t  dest_mac[IFHWADDRLEN];
	uint8_t  src_mac[IFHWADDRLEN];
	uint8_t  bssid[IFHWADDRLEN];
	struct sequence_control sc;
	uint8_t  frame_body[];
} __attribute__((__packed__));


void init_dev(struct dev *dev);
int iw_open(struct dev *dev);
void iw_close(struct dev *dev);
ssize_t iw_write(int fd, void *buf, size_t count);
ssize_t iw_read(int fd, void *buf, size_t count, uint8_t **pkt, size_t *pkt_sz);
int iw_set_channel(struct dev *dev, int chan);
int send_deauth(int fd, unsigned char *ap_mac);
int read_bssid(int fd, uint8_t *bssid);
void print_mac(uint8_t *mac);

#endif

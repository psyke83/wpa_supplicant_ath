/*
 * Sigma Control API DUT (station/AP)
 * Copyright (c) 2010, Atheros Communications, Inc.
 */

#include "sigma_dut.h"
#include "wpa_helpers.h"

#define SIGMA_DUT_PORT 9000
#define MAX_CONNECTIONS 4


static struct sigma_dut sigma_dut;


void sigma_dut_print(struct sigma_dut *dut, int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (level >= dut->debug_level) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		printf("%ld.%06u: ", (long) tv.tv_sec,
		       (unsigned int) tv.tv_usec);
		vprintf(fmt, ap);
		printf("\n");
	}
	va_end(ap);
}


int sigma_dut_reg_cmd(const char *cmd,
		      int (*validate)(struct sigma_cmd *cmd),
		      int (*process)(struct sigma_dut *dut,
				     struct sigma_conn *conn,
				     struct sigma_cmd *cmd))
{
	struct sigma_cmd_handler *h;
	size_t clen, len;

	clen = strlen(cmd);
	len = sizeof(*h) + clen + 1;
	h = malloc(len);
	if (h == NULL)
		return -1;
	memset(h, 0, len);
	h->cmd = (char *) (h + 1); /* include in same allocation */
	memcpy(h->cmd, cmd, clen);
	h->validate = validate;
	h->process= process;

	h->next = sigma_dut.cmds;
	sigma_dut.cmds = h;

	return 0;
}


static int open_socket(struct sigma_dut *dut, int port)
{
	struct sockaddr_in addr;
	int val;

	dut->s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (dut->s < 0) {
		sigma_dut_print(dut, DUT_MSG_ERROR, "socket: %s",
				strerror(errno));
		return -1;
	}

	val = 1;
	if (setsockopt(dut->s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) <
	    0)
		sigma_dut_print(dut, DUT_MSG_INFO, "setsockopt SO_REUSEADDR: "
				"%s", strerror(errno));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (bind(dut->s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		sigma_dut_print(dut, DUT_MSG_ERROR, "bind: %s",
				strerror(errno));
		goto fail;
	}

	if (listen(dut->s, 5) < 0) {
		sigma_dut_print(dut, DUT_MSG_ERROR, "listen: %s",
				strerror(errno));
		goto fail;
	}

	return 0;

fail:
	close(dut->s);
	dut->s = -1;
	return -1;
}


static void close_socket(struct sigma_dut *dut)
{
	close(dut->s);
	dut->s = -1;
}


void send_resp(struct sigma_dut *dut, struct sigma_conn *conn,
	       enum sigma_status status, char *buf)
{
	struct msghdr msg;
	struct iovec iov[4];
	size_t elems;

	sigma_dut_print(dut, DUT_MSG_INFO, "resp: status=%d buf=%s",
			status, buf);

	iov[0].iov_base = "status,";
	iov[0].iov_len = 7;
	switch (status) {
	case SIGMA_RUNNING:
		iov[1].iov_base = "RUNNING,";
		iov[1].iov_len = 8;
		break;
	case SIGMA_INVALID:
		iov[1].iov_base = "INVALID,";
		iov[1].iov_len = 8;
		break;
	case SIGMA_ERROR:
		iov[1].iov_base = "ERROR,";
		iov[1].iov_len = 6;
		break;
	case SIGMA_COMPLETE:
		iov[1].iov_base = "COMPLETE,";
		iov[1].iov_len = 9;
		break;
	}
	if (buf) {
		iov[2].iov_base = buf;
		iov[2].iov_len = strlen(buf);
		iov[3].iov_base = "\r\n";
		iov[3].iov_len = 2;
		elems = 4;
	} else {
		iov[1].iov_len--;
		iov[2].iov_base = "\r\n";
		iov[2].iov_len = 2;
		elems = 3;
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = elems;
	if (sendmsg(conn->s, &msg, 0) < 0)
		sigma_dut_print(dut, DUT_MSG_INFO, "sendmsg: %s",
				strerror(errno));
}


const char * get_param(struct sigma_cmd *cmd, const char *name)
{
	int i;
	for (i = 0; i < cmd->count; i++) {
		if (strcasecmp(name, cmd->params[i]) == 0)
			return cmd->values[i];
	}
	return NULL;
}


static void process_cmd(struct sigma_dut *dut, struct sigma_conn *conn,
			char *buf)
{
	struct sigma_cmd_handler *h;
	struct sigma_cmd c;
	char *cmd, *pos, *pos2;
	int len;
	char txt[200];
	int res;

	while (*buf == '\r' || *buf == '\n' || *buf == '\t' || *buf == ' ')
		buf++;
	len = strlen(buf);
	while (len > 0 && buf[len - 1] == ' ') {
		buf[len - 1] = '\0';
		len--;
	}

	sigma_dut_print(dut, DUT_MSG_INFO, "cmd: %s", buf);
	snprintf(txt, sizeof(txt), "NOTE CAPI:%s", buf);
	txt[sizeof(txt) - 1] = '\0';
	wpa_command(get_main_ifname(), txt);

	memset(&c, 0, sizeof(c));
	cmd = buf;
	pos = strchr(cmd, ',');
	if (pos) {
		*pos++ = '\0';
		if (strcasecmp(cmd, "AccessPoint") == 0 ||
		    strcasecmp(cmd, "PowerSwitch") == 0) {
			pos2 = strchr(pos, ',');
			if (pos2 == NULL)
				goto invalid_params;
			c.params[c.count] = pos;
			c.values[c.count] = pos2;
			c.count++;
			pos = strchr(pos2, ',');
			if (pos)
				*pos++ = '\0';
		}
		while (pos) {
			pos2 = strchr(pos, ',');
			if (pos2 == NULL)
				goto invalid_params;
			*pos2++ = '\0';
			if (c.count == MAX_PARAMS) {
				sigma_dut_print(dut, DUT_MSG_INFO, "Too many "
						"parameters");
				goto invalid_params;
			}
			c.params[c.count] = pos;
			c.values[c.count] = pos2;
			c.count++;
			pos = strchr(pos2, ',');
			if (pos)
				*pos++ = '\0';
		}
	}
	h = dut->cmds;
	while (h) {
		if (strcasecmp(cmd, h->cmd) == 0)
			break;
		h = h->next;
	}

	if (h == NULL) {
		sigma_dut_print(dut, DUT_MSG_INFO, "Unknown command: '%s'",
				cmd);
		send_resp(dut, conn, SIGMA_INVALID,
			  "errorCode,Unknown command");
		return;
	}

	if (h->validate && h->validate(&c) < 0) {
	invalid_params:
		sigma_dut_print(dut, DUT_MSG_INFO, "Invalid parameters");
		send_resp(dut, conn, SIGMA_INVALID, "errorCode,Invalid "
			  "parameters");
		return;
	}

	send_resp(dut, conn, SIGMA_RUNNING, NULL);
	sigma_dut_print(dut, DUT_MSG_INFO, "Run command: %s", cmd);
	res = h->process(dut, conn, &c);
	if (res == -2)
		send_resp(dut, conn, SIGMA_ERROR, NULL);
	else if (res == -1)
		send_resp(dut, conn, SIGMA_INVALID, NULL);
	else if (res == 1)
		send_resp(dut, conn, SIGMA_COMPLETE, NULL);
}


static void process_conn(struct sigma_dut *dut, struct sigma_conn *conn)
{
	ssize_t res;
	int i;

	sigma_dut_print(dut, DUT_MSG_DEBUG, "Read from %s:%d",
			inet_ntoa(conn->addr.sin_addr),
			ntohs(conn->addr.sin_port));

	res = recv(conn->s, conn->buf + conn->pos, MAX_CMD_LEN + 5 - conn->pos,
		   0);
	if (res < 0) {
		sigma_dut_print(dut, DUT_MSG_INFO, "recv: %s",
				strerror(errno));
	}
	if (res <= 0) {
		sigma_dut_print(dut, DUT_MSG_DEBUG, "Close connection from "
				"%s:%d",
				inet_ntoa(conn->addr.sin_addr),
				ntohs(conn->addr.sin_port));
		close(conn->s);
		conn->s = -1;
		return;
	}

	sigma_dut_print(dut, DUT_MSG_DEBUG, "Received %d bytes",
			(int) res);

	for (;;) {
		for (i = conn->pos; i < conn->pos + res; i++) {
			if (conn->buf[i] == '\r' || conn->buf[i] == '\n')
				break;
		}

		if (i == conn->pos + res) {
			/* Full command not yet received */
			conn->pos += res;
			if (conn->pos >= MAX_CMD_LEN + 5) {
				sigma_dut_print(dut, DUT_MSG_INFO, "Too long "
						"command dropped");
				conn->pos = 0;
			}
			break;
		}

		/* Full command received */
		conn->buf[i++] = '\0';
		process_cmd(dut, conn, conn->buf);
		if (i < conn->pos + res &&
		    (conn->buf[i] == '\r' || conn->buf[i] == '\n'))
			i++;
		memmove(conn->buf, &conn->buf[i], conn->pos + res - i);
		res = conn->pos + res - i;
		conn->pos = 0;
	}
}


static void run_loop(struct sigma_dut *dut)
{
	struct sigma_conn conn[MAX_CONNECTIONS];
	int i, res, maxfd, can_accept;
	fd_set rfds;

	for (i = 0; i < MAX_CONNECTIONS; i++)
		conn[i].s = -1;

	for (;;) {
		FD_ZERO(&rfds);
		maxfd = -1;
		can_accept = 0;
		for (i = 0; i < MAX_CONNECTIONS; i++) {
			if (conn[i].s >= 0) {
				FD_SET(conn[i].s, &rfds);
				if (conn[i].s > maxfd)
					maxfd = conn[i].s;
			} else
				can_accept = 1;
		}

		if (can_accept) {
			FD_SET(dut->s, &rfds);
			if (dut->s > maxfd)
				maxfd = dut->s;
		}


		sigma_dut_print(dut, DUT_MSG_DEBUG, "Waiting for next "
				"command (can_accept=%d)", can_accept);
		res = select(maxfd + 1, &rfds, NULL, NULL, NULL);
		if (res < 0) {
			perror("select");
			sleep(1);
			continue;
		}

		if (!res) {
			sigma_dut_print(dut, DUT_MSG_DEBUG, "Nothing ready");
			sleep(1);
			continue;
		}

		if (FD_ISSET(dut->s, &rfds)) {
			for (i = 0; i < MAX_CONNECTIONS; i++) {
				if (conn[i].s < 0)
					break;
			}
			conn[i].addrlen = sizeof(conn[i].addr);
			conn[i].s = accept(dut->s,
					   (struct sockaddr *) &conn[i].addr,
					   &conn[i].addrlen);
			if (conn[i].s < 0) {
				sigma_dut_print(dut, DUT_MSG_INFO,
						"accept: %s",
						strerror(errno));
				continue;
			}

			sigma_dut_print(dut, DUT_MSG_DEBUG,
					"Connection %d from %s:%d", i,
					inet_ntoa(conn[i].addr.sin_addr),
					ntohs(conn[i].addr.sin_port));
			conn[i].pos = 0;
		}

		for (i = 0; i < MAX_CONNECTIONS; i++) {
			if (conn[i].s < 0)
				continue;
			if (FD_ISSET(conn[i].s, &rfds))
				process_conn(dut, &conn[i]);
		}
	}
}


int main(int argc, char *argv[])
{
	int c;
	int daemonize = 0;
	int port = SIGMA_DUT_PORT;

	memset(&sigma_dut, 0, sizeof(sigma_dut));
	sigma_dut.debug_level = DUT_MSG_INFO;
	sigma_dut.default_timeout = 120;

	for (;;) {
		c = getopt(argc, argv, "b:Bdhp:qs:");
		if (c < 0)
			break;
		switch (c) {
		case 'b':
			sigma_dut.bridge = optarg;
			break;
		case 'B':
			daemonize++;
			break;
		case 'd':
			if (sigma_dut.debug_level > 0)
				sigma_dut.debug_level--;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'q':
			sigma_dut.debug_level++;
			break;
		case 's':
			sigma_dut.sniffer_ifname = optarg;
			break;
		case 'h':
		default:
			printf("usage: sigma_dut [-Bdq] [-p<port>] "
			       "[-s<sniffer>]\n");
			exit(0);
			break;
		}
	}

	sigma_dut_register_cmds();

	if (open_socket(&sigma_dut, port) < 0)
		return -1;

	if (daemonize) {
		if (daemon(0, 0) < 0) {
			perror("daemon");
			exit(-1);
		}
	}

	run_loop(&sigma_dut);

	close_socket(&sigma_dut);
	return 0;
}

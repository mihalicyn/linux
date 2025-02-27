// SPDX-License-Identifier: GPL-2.0 OR MIT
#define _GNU_SOURCE
#include <error.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../kselftest_harness.h"
#include "cgroup_util.h"

#define clean_errno() (errno == 0 ? "None" : strerror(errno))
#define log_err(MSG, ...)                                                   \
	fprintf(stderr, "(%s:%d: errno: %s) " MSG "\n", __FILE__, __LINE__, \
		clean_errno(), ##__VA_ARGS__)

#ifndef SO_PEERCGROUPID
#define SO_PEERCGROUPID 83
#endif

static void child_die()
{
	exit(1);
}

struct sock_addr {
	char sock_name[32];
	struct sockaddr_un listen_addr;
	socklen_t addrlen;
};

FIXTURE(so_peercgroupid)
{
	int server;
	pid_t client_pid;
	int sync_sk[2];
	struct sock_addr server_addr;
	struct sock_addr *client_addr;
	char cgroup_root[PATH_MAX];
	char *test_cgroup1;
	char *test_cgroup2;
};

FIXTURE_VARIANT(so_peercgroupid)
{
	int type;
	bool abstract;
};

FIXTURE_VARIANT_ADD(so_peercgroupid, stream_pathname)
{
	.type = SOCK_STREAM,
	.abstract = 0,
};

FIXTURE_VARIANT_ADD(so_peercgroupid, stream_abstract)
{
	.type = SOCK_STREAM,
	.abstract = 1,
};

FIXTURE_VARIANT_ADD(so_peercgroupid, seqpacket_pathname)
{
	.type = SOCK_SEQPACKET,
	.abstract = 0,
};

FIXTURE_VARIANT_ADD(so_peercgroupid, seqpacket_abstract)
{
	.type = SOCK_SEQPACKET,
	.abstract = 1,
};

FIXTURE_VARIANT_ADD(so_peercgroupid, dgram_pathname)
{
	.type = SOCK_DGRAM,
	.abstract = 0,
};

FIXTURE_VARIANT_ADD(so_peercgroupid, dgram_abstract)
{
	.type = SOCK_DGRAM,
	.abstract = 1,
};

FIXTURE_SETUP(so_peercgroupid)
{
	self->client_addr = mmap(NULL, sizeof(*self->client_addr), PROT_READ | PROT_WRITE,
				 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	ASSERT_NE(MAP_FAILED, self->client_addr);

	self->cgroup_root[0] = '\0';
}

FIXTURE_TEARDOWN(so_peercgroupid)
{
	close(self->server);

	kill(self->client_pid, SIGKILL);
	waitpid(self->client_pid, NULL, 0);

	if (!variant->abstract) {
		unlink(self->server_addr.sock_name);
		unlink(self->client_addr->sock_name);
	}

	if (strlen(self->cgroup_root) > 0) {
		cg_enter_current(self->cgroup_root);

		if (self->test_cgroup1)
			cg_destroy(self->test_cgroup1);
		free(self->test_cgroup1);

		if (self->test_cgroup2)
			cg_destroy(self->test_cgroup2);
		free(self->test_cgroup2);
	}
}

static void fill_sockaddr(struct sock_addr *addr, bool abstract)
{
	char *sun_path_buf = (char *)&addr->listen_addr.sun_path;

	addr->listen_addr.sun_family = AF_UNIX;
	addr->addrlen = offsetof(struct sockaddr_un, sun_path);
	snprintf(addr->sock_name, sizeof(addr->sock_name), "so_peercgroupid_%d", getpid());
	addr->addrlen += strlen(addr->sock_name);
	if (abstract) {
		*sun_path_buf = '\0';
		addr->addrlen++;
		sun_path_buf++;
	} else {
		unlink(addr->sock_name);
	}
	memcpy(sun_path_buf, addr->sock_name, strlen(addr->sock_name));
}

static void client(FIXTURE_DATA(so_peercgroupid) *self,
		   const FIXTURE_VARIANT(so_peercgroupid) *variant)
{
	int cfd, err;
	socklen_t len;
	uint64_t peer_cgroup_id = 0, test_cgroup1_id = 0, test_cgroup2_id = 0;
	char state;

	cfd = socket(AF_UNIX, variant->type, 0);
	if (cfd < 0) {
		log_err("socket");
		child_die();
	}

	if (variant->type == SOCK_DGRAM) {
		fill_sockaddr(self->client_addr, variant->abstract);

		if (bind(cfd, (struct sockaddr *)&self->client_addr->listen_addr, self->client_addr->addrlen)) {
			log_err("bind");
			child_die();
		}
	}

	/* negative testcase: no peer for socket yet */
	len = sizeof(peer_cgroup_id);
	err = getsockopt(cfd, SOL_SOCKET, SO_PEERCGROUPID, &peer_cgroup_id, &len);
	if (!err || (errno != ENODATA)) {
		log_err("getsockopt must fail with errno == ENODATA when socket has no peer");
		child_die();
	}

	if (connect(cfd, (struct sockaddr *)&self->server_addr.listen_addr,
		    self->server_addr.addrlen) != 0) {
		log_err("connect");
		child_die();
	}

	state = 'R';
	write(self->sync_sk[1], &state, sizeof(state));

	read(self->sync_sk[1], &test_cgroup1_id, sizeof(uint64_t));
	read(self->sync_sk[1], &test_cgroup2_id, sizeof(uint64_t));

	len = sizeof(peer_cgroup_id);
	if (getsockopt(cfd, SOL_SOCKET, SO_PEERCGROUPID, &peer_cgroup_id, &len)) {
		log_err("Failed to get SO_PEERCGROUPID");
		child_die();
	}

	/*
	 * There is a difference between connection-oriented sockets
	 * and connectionless ones from the perspective of SO_PEERCGROUPID.
	 *
	 * sk->sk_cgrp_data is getting filled when we allocate struct sock (see call to cgroup_sk_alloc()).
	 * For DGRAM socket, self->server socket is our peer and by the time when we allocate it,
	 * parent process sits in a test_cgroup1. Then it changes cgroup to test_cgroup2, but it does not
	 * affect anything.
	 * For STREAM/SEQPACKET socket, self->server is not our peer, but that one we get from accept()
	 * syscall. And by the time when we call accept(), parent process sits in test_cgroup2.
	 *
	 * Let's ensure that it works like that and if it get changed then we should detect it
	 * as it's a clear UAPI change.
	 */
	if (variant->type == SOCK_DGRAM) {
		/* cgroup id from SO_PEERCGROUPID should be equal to the test_cgroup1_id */
		if (peer_cgroup_id != test_cgroup1_id) {
			log_err("peer_cgroup_id != test_cgroup1_id: %" PRId64 " != %" PRId64, peer_cgroup_id, test_cgroup1_id);
			child_die();
		}
	} else {
		/* cgroup id from SO_PEERCGROUPID should be equal to the test_cgroup2_id */
		if (peer_cgroup_id != test_cgroup2_id) {
			log_err("peer_cgroup_id != test_cgroup2_id: %" PRId64 " != %" PRId64, peer_cgroup_id, test_cgroup2_id);
			child_die();
		}
	}
}

TEST_F(so_peercgroupid, test)
{
	uint64_t test_cgroup1_id, test_cgroup2_id;
	int err;
	int pfd;
	char state;
	int child_status = 0;

	if (cg_find_unified_root(self->cgroup_root, sizeof(self->cgroup_root), NULL))
		ksft_exit_skip("cgroup v2 isn't mounted\n");

	self->test_cgroup1 = cg_name(self->cgroup_root, "so_peercgroupid_cg1");
	ASSERT_NE(NULL, self->test_cgroup1);

	self->test_cgroup2 = cg_name(self->cgroup_root, "so_peercgroupid_cg2");
	ASSERT_NE(NULL, self->test_cgroup2);

	err = cg_create(self->test_cgroup1);
	ASSERT_EQ(0, err);

	err = cg_create(self->test_cgroup2);
	ASSERT_EQ(0, err);

	test_cgroup1_id = cg_get_id(self->test_cgroup1);
	ASSERT_LT(0, test_cgroup1_id);

	test_cgroup2_id = cg_get_id(self->test_cgroup2);
	ASSERT_LT(0, test_cgroup2_id);

	/* enter test_cgroup1 before allocating a socket */
	err = cg_enter_current(self->test_cgroup1);
	ASSERT_EQ(0, err);

	self->server = socket(AF_UNIX, variant->type, 0);
	ASSERT_NE(-1, self->server);

	/* enter test_cgroup2 after allocating a socket */
	err = cg_enter_current(self->test_cgroup2);
	ASSERT_EQ(0, err);

	fill_sockaddr(&self->server_addr, variant->abstract);

	err = bind(self->server, (struct sockaddr *)&self->server_addr.listen_addr, self->server_addr.addrlen);
	ASSERT_EQ(0, err);

	if (variant->type != SOCK_DGRAM) {
		err = listen(self->server, 1);
		ASSERT_EQ(0, err);
	}

	err = socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, self->sync_sk);
	EXPECT_EQ(err, 0);

	self->client_pid = fork();
	ASSERT_NE(-1, self->client_pid);
	if (self->client_pid == 0) {
		close(self->server);
		close(self->sync_sk[0]);
		client(self, variant);
		exit(0);
	}
	close(self->sync_sk[1]);

	if (variant->type != SOCK_DGRAM) {
		pfd = accept(self->server, NULL, NULL);
		ASSERT_NE(-1, pfd);
	} else {
		pfd = self->server;
	}

	/* wait until the child arrives at checkpoint */
	read(self->sync_sk[0], &state, sizeof(state));
	ASSERT_EQ(state, 'R');

	write(self->sync_sk[0], &test_cgroup1_id, sizeof(uint64_t));
	write(self->sync_sk[0], &test_cgroup2_id, sizeof(uint64_t));

	close(pfd);
	waitpid(self->client_pid, &child_status, 0);
	ASSERT_EQ(0, WIFEXITED(child_status) ? WEXITSTATUS(child_status) : 1);
}

TEST_HARNESS_MAIN

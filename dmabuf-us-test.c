/*
 * Copyright(C) 2011 Linaro Limited. All rights reserved.
 * Author: Benjamin Gaignard <benjamin.gaignard@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * arm-linux-gnueabi-gcc drivers/base/test.c -o drivers/base/test -Wall
 *
 * before run the test don't forget to mount debugfs
 * mount -t debugfs none /sys/kernel/debug
 */

#include "dma-buf-test.h"
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/wait.h>

#define SRC_NAME  "/sys/kernel/debug/dma-buf_test/src"
#define SINK_NAME "/sys/kernel/debug/dma-buf_test/sink"

#define MULTIPLE_SEND_BUFFER 3

int open_source_file(int mmap)
{
	int fd = 0;

	if (mmap)
		fd = open(SRC_NAME, O_RDWR);
	else
		fd = open(SRC_NAME, 0);

	if (fd < 0) {
		printf("can't open %s\n", SRC_NAME);
		return 0;
	}
	return fd;
}

int open_sink_file(void)
{
	int fd = open(SINK_NAME, O_RDWR);

	if (fd < 0) {
		printf("can't open %s\n", SINK_NAME);
		return 0;
	}

	return fd;
}

int test_check_pattern(char *m)
{
	int i, j;
	for (j = 0; j < NB_OF_BUFFERS; j++) {
		for (i = 0; i < BUFFER_SIZE; i++, m++) {
			if (*m != j) {
				printf("check pattern failed\n");
				return 0;
			}
		}
	}
	return 1;
}

/* test if mmap on buffer is working has expected
* if mmap_enable is set to true mmap must work
* else mmap must fail
* return true if test in OK */
int test_mmap(int mmap_enable)
{

	int buf_fd;
	int src = open_source_file(mmap_enable);
	char *mmap_addr;

	printf("start test_mmap %s\n", mmap_enable == 0 ? "disable" : "enable");
	if (!src)
		return 0;

	printf("ask a new buffer-object file descriptor\n");
	if (ioctl(src, TEST_GET_FD, &buf_fd) < 0) {
		printf("can't get a buffer file descriptor\n");
		goto err;
	}

	mmap_addr =
	    (char *)mmap(NULL, BUFFER_SIZE * NB_OF_BUFFERS,
			 PROT_READ | PROT_WRITE, MAP_SHARED, buf_fd, 0);

	if (mmap_enable == (mmap_addr == MAP_FAILED)) {
		printf("error on mmap function\n");
		goto err;
	}

	if (mmap_enable) {
		if (!test_check_pattern(mmap_addr))
			goto err;
	}

	ioctl(src, TEST_PUT_BUFFER, &buf_fd);

	printf("test_mmap %s success\n",
	       mmap_enable == 0 ? "disable" : "enable");
	close(src);
	return 1;

err:
	printf("test_mmap %s failed\n",
	       mmap_enable == 0 ? "disable" : "enable");
	close(src);
	return 0;
}

int test_buffer_refcount(void)
{
	int buf_fd;
	int src = open_source_file(1);
	int sink = open_sink_file();

	printf("test_buffer_refcount\n");

	printf("ask a new buffer-object file descriptor\n");
	if (ioctl(src, TEST_GET_FD, &buf_fd) < 0) {
		printf("can't get a buffer file descriptor\n");
		goto err;
	}

	printf("do get operation on buffer\n");
	ioctl(sink, TEST_GET_BUFFER, &buf_fd);

	printf("release the buffer\n");
	ioctl(sink, TEST_PUT_BUFFER, &buf_fd);

	printf("test_buffer_refcount success\n");
	close(sink);
	close(src);
	return 1;

err:
	printf("test_buffer_refcount failed\n");
	close(sink);
	close(src);
	return 0;
}

/* multi process test functions */
int test_receive_fd(int sk, int *fd)
{
	int ret;
	char data[10];
	char cmsg_b[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct msghdr msgh;
	struct iovec iov;

	memset(&msgh, 0, sizeof(msgh));

	msgh.msg_control = &cmsg_b;
	msgh.msg_controllen = CMSG_LEN(sizeof(int));

	iov.iov_base = data;
	iov.iov_len = sizeof(data) - 1;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

	cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));

	ret = recvmsg(sk, &msgh, 0);
	if (ret < 0) {
		printf("recvmsg failed");
		return -errno;
	}

	*fd = *((int *)CMSG_DATA(cmsg));
	printf("receive file descriptor %d\n", *fd);

	return 0;
}

int test_client(int sk)
{
	int buf_fd, i;

	for (i = 0; i < MULTIPLE_SEND_BUFFER; i++) {
		printf("client wait for message\n");
		if (test_receive_fd(sk, &buf_fd) < 0) {
			printf("failed to receive a file descriptor\n");
		} else {
			char *mmap_addr =
			    (char *)mmap(NULL, BUFFER_SIZE * NB_OF_BUFFERS,
					 PROT_READ | PROT_WRITE, MAP_SHARED,
					 buf_fd, 0);
			if (mmap_addr != MAP_FAILED) {
				if (!test_check_pattern(mmap_addr))
					break;
			}

		}
	}
	return 1;
}

/* send an file descriptor through a socket*/
int test_send_fd(int sk, int fd)
{
	char cmsg_b[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct msghdr msgh;
	struct iovec iov;

	printf("send file descriptor %d\n", fd);
	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_control = &cmsg_b;
	msgh.msg_controllen = CMSG_LEN(sizeof(int));

	iov.iov_base = "OK";
	iov.iov_len = 2;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

	cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	/* Initialize the payload */
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	return sendmsg(sk, &msgh, MSG_NOSIGNAL);
}

/* a small server
 * it create a socket and wait for client connection
 * then send buffer-object file descriptors */
int test_server(int sk)
{
	int i;
	int buf_fd;
	int src = open_source_file(1);

	if (!src)
		return -1;

	printf("start server\n");
	/* get buffer-object file descriptors and send them */
	for (i = 0; i < MULTIPLE_SEND_BUFFER; i++) {
		printf("ask a new buffer-object file descriptor\n");
		if (ioctl(src, TEST_GET_FD, &buf_fd) < 0) {
			printf("can't get a buffer file descriptor\n");
			goto err;
		}

		printf("do get operation on buffer\n");
		ioctl(src, TEST_GET_BUFFER, &buf_fd);

		test_send_fd(sk, buf_fd);

		ioctl(src, TEST_PUT_BUFFER, &buf_fd);
	}
	sleep(1);
	close(src);
	return 1;

err:
	close(src);
	return 0;
}

int test_multiprocess(void)
{
	int pair[2];
	pid_t pid;

	printf("test multi process buffer sharing\n");

	printf("try to open a socketpair\n");
	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pair) < 0) {
		printf("socketpair PF_LOCAL failed\n");
		return 0;
	}

	pid = fork();
	if (pid == 0) {
		/* child */
		test_server(pair[0]);
		close(pair[0]);
	} else if (pid < 0) {
		/* error */
		printf("fork failed\n");
		close(pair[0]);
		close(pair[1]);
		return 0;
	} else {
		/* parent */
		test_client(pair[1]);
		close(pair[1]);
	}
	return 1;
}

int main(int argc, char **argv)
{
	printf("don't forget to mount debugfs before run this test\n");
	printf("mount -t debugfs none /sys/kernel/debug\n");

	test_buffer_refcount();
	sleep(1);

	test_mmap(0);
	sleep(1);

	test_mmap(1);
	sleep(1);

	test_multiprocess();

	return 0;
}

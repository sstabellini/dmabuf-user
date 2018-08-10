/*
 * Copyright(C) 2011 Linaro Limited. All rights reserved.
 * Author: Benjamin Gaignard <benjamin.gaignard@linaro.org>
 * Author: Stefano Stabellini <stefanos@xilinx.com>
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
 * arm-linux-gnueabi-gcc -static dmabuf-us-test.c -o dmabuf-us-test -Wall
 *
 * before run the test don't forget to mount debugfs:
 * mount -t debugfs none /sys/kernel/debug
 */

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

#define SRC_NAME  "/dev/xen_mem"

#define MULTIPLE_SEND_BUFFER 1
#define BUFFER_SIZE 4096
#define NB_OF_BUFFERS 1
#define TEST_GET_FD 0

int open_source_file(void)
{
	int fd = 0;

	fd = open(SRC_NAME, 0);
	if (fd < 0) {
		printf("can't open %s, %d\n", SRC_NAME,errno);
		return 0;
	}
	return fd;
}

int test_check_pattern(char *m)
{
	int i, j;
	for (j = 0; j < NB_OF_BUFFERS; j++) {
		for (i = 0; i < BUFFER_SIZE; i++, m++) {
			if (*m != '$') {
				printf("check pattern failed\n");
				return 0;
			}
		}
	}
	return 1;
}

int write_pattern(char *m)
{
	int i, j;
	printf("writing patter\n");
	for (j = 0; j < NB_OF_BUFFERS; j++) {
		for (i = 0; i < BUFFER_SIZE; i++, m++) {
			*m = '$';
		}
	}
	return 1;
}

/* test if mmap on buffer is working has expected
* if mmap_enable is set to true mmap must work
* else mmap must fail
* return true if test in OK */
int test_mmap(void)
{

	int buf_fd;
	int src = open_source_file();
	char *mmap_addr;

	printf("Start test_mmap, device file=%s fd=%d\n", SRC_NAME, src);
	if (!src)
		return 0;

	if (ioctl(src, TEST_GET_FD, &buf_fd) < 0) {
		printf("can't get a buffer file descriptor\n");
		goto err;
	}
	printf("IOCTL returned fd=%d\n\n", buf_fd);

	mmap_addr =
	    (char *)mmap(NULL, BUFFER_SIZE * NB_OF_BUFFERS,
			 PROT_READ | PROT_WRITE, MAP_SHARED, buf_fd, 0);

	if (mmap_addr == MAP_FAILED) {
		printf("error on mmap function\n");
		goto err;
	}

	printf("MMAP successful, virt_addr=%p\n\n", mmap_addr);

	if (!test_check_pattern(mmap_addr))
	{
		write_pattern(mmap_addr);
	}

	printf("test_mmap success\n");
	close(src);
	return 1;

err:
	printf("test_mmap %s failed\n");
	
	close(src);
	return 0;
}

int main(int argc, char **argv)
{
	test_mmap();
	return 0;
}

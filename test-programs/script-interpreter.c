// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <linux/fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	char *args[] = { NULL, NULL };
	char *env[] = { NULL };
	FILE *input;
	unsigned int value = 0;
	int ch, error;
	long result;

	if (argc != 2)
		return 2;
	args[0] = argv[1];
	input = strcmp(argv[1], "--stdin") ? fopen(argv[1], "r") : stdin;
	if (!input) {
		perror("open script");
		return 2;
	}

	/* Check and interpret the same fd; do not read script bytes before ALLOW. */
	result = syscall(SYS_execveat, fileno(input), "", args, env,
			 AT_EMPTY_PATH | AT_EXECVE_CHECK);
	error = result ? errno : 0;
	fprintf(stderr, "execveat errno=%d\n", error);
	if (result)
		return 1;

	/* This deliberately small language only increments a counter. */
	while ((ch = fgetc(input)) != EOF) {
		if (ch == '+')
			value++;
		else if (ch != '\n')
			return 2;
	}
	if (ferror(input))
		return 2;
	if (fclose(input))
		return 2;
	return printf("%u\n", value) < 0 ? 2 : 0;
}

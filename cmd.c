#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "mvi.h"

static pid_t
cmd_exec(char *argv[], int *ifd, int *ofd, int *efd)
{
	pid_t pid;
	int pipe0[2];
	int pipe1[2];
	int pipe2[2];
	
	if (ifd && pipe(pipe0) != 0)
		goto fail;
	if (ofd && pipe(pipe1) != 0)
		goto fail;
	if (efd && pipe(pipe2) != 0)
		goto fail;

	if (ifd) {
		int got = fcntl(pipe0[1], F_GETFL);
		if (got > 0)
			fcntl(pipe0[1], F_SETFL, got | O_NONBLOCK);
	}

	switch ((pid = fork())) {
	case 0:
		if (ifd) {
			dup2(pipe0[0], 0);
			close(pipe0[1]);
			close(pipe0[0]);
		}
		if (ofd) {
			dup2(pipe1[1], 1);
			close(pipe1[0]);
			close(pipe1[1]);
		}
		if (efd) {
			dup2(pipe2[1], 2);
			close(pipe1[0]);
			close(pipe1[1]);
		}
		execvp(argv[0], argv);
		exit(-1);
	default:
		if (ifd) close(pipe0[0]);
		if (ofd) close(pipe1[1]);
		if (efd) close(pipe2[1]);
		if (pid < 0) {
fail:
			return 0;
		}
	}
	if (ifd) *ifd = pipe0[1];
	if (ofd) *ofd = pipe1[0];
	if (efd) *efd = pipe2[0];
	return pid;
}

int
cmd_pipe(char *argv[],
    char *input, size_t inlen,
    char **output, size_t *outlen,
    char **error, size_t *errlen)
{
	char buf[512];
	sbuf_t *obuf, *ebuf;
	sigset_t mask, orig_mask;
	pid_t pid;
	int ifd = -1, ofd = -1, efd = -1;
	int r = 0;

	obuf = 0;
	ebuf = 0;

	pid = cmd_exec(argv,
	    input ? &ifd : 0,
	    output ? &ofd : 0,
	    error ? &efd : 0);
	if (pid < 0)
		goto fail;

	obuf = 0, ebuf = 0;
	if (output) obuf = sbuf_make();
	if (error) ebuf = sbuf_make();

	sigemptyset(&mask);
	sigaddset(&mask, SIGPIPE);
	sigprocmask(SIG_BLOCK, &mask, &orig_mask);


	struct pollfd fds[3];
	fds[0].fd = ofd;
	fds[0].events = POLLIN | POLLHUP;
	fds[1].fd = ifd;
	fds[1].events = POLLOUT;
	fds[2].fd = efd;
	fds[2].events = POLLIN | POLLHUP;

	while ((fds[0].fd >= 0 || fds[1].fd >= 0 || fds[2].fd >= 0) &&
	    poll(fds, 3, -1) >= 0) {
		// stdout
		if (fds[0].revents & POLLIN) {
			ssize_t ret = read(fds[0].fd, buf, sizeof (buf));
			/* fprintf(stderr, "stdout: ret=%d\n", */
			/*     ret); */
			if (ret > 0)
				sbuf_strn(obuf, buf, ret);
			else
				close(fds[0].fd);
		} else if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
			fds[0].fd = -1;
		}
		// stdin
		if (fds[1].revents & POLLOUT) {
			ssize_t ret = write(fds[1].fd, input, inlen);
			if (ret > 0) {
				input += ret;
				inlen -= ret;
			}
			if (ret <= 0 && errno == EAGAIN) {
				/* ignore */
			} else if (ret <= 0 || inlen == 0) {
				close(fds[1].fd);
			}
		} else if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
			fds[1].fd = -1;
		}
		// stderr
		if (fds[2].revents & POLLIN) {
			ssize_t ret = read(fds[2].fd, buf, sizeof (buf));
			/* fprintf(stderr, "stderr: ret=%d\n", */
			/*     ret); */
			if (ret > 0)
				sbuf_strn(ebuf, buf, sizeof (buf));
			else
				close(fds[2].fd);
		} else if (fds[2].revents & (POLLERR | POLLHUP | POLLNVAL)) {
			fds[2].fd = -1;
		}
	}

	if (input) close(ifd);
	if (output) close(ofd);
	if (error) close(efd);

	int status;
	waitpid(pid, &status, 0);
	r = WEXITSTATUS(status);

	if (output)
		*outlen = sbuf_done(obuf, output);
	if (error)
		*errlen = sbuf_done(ebuf, error);

	if (0) {
fail:
		*outlen = 0;
		*errlen = 0;
		if (obuf) sbuf_free(obuf);
		if (ebuf) sbuf_free(ebuf);
		r = -1;
	}

	sigpending(&mask);
	if (sigismember(&mask, SIGPIPE)) {
		int sig;
		sigwait(&mask, &sig);
	}
	sigprocmask(SIG_SETMASK, &orig_mask, 0);

	return r;
}

int
cmd_pipesh(char *cmd,
    char *input, size_t inlen,
    char **output, size_t *outlen,
    char **error, size_t *errlen)
{
	char *argv[] = {"/bin/sh", "-c", cmd, NULL};
	return cmd_pipe(argv, input, inlen, output, outlen, error, errlen);
}

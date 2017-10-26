#include <sys/ioctl.h>
#include <sys/wait.h>

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>
#include <poll.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "blaze822.h"

#define TK_CTL(x)	((x) & 037)
#define TK_INT(c)	((c) < 0 || (c) == TK_ESC || (c) == TK_CTL('c'))
#define TK_ESC		(TK_CTL('['))

#define LEN(a)		(sizeof(a) / sizeof((a)[0]))
#define MIN(a, b)	((a) < (b) ? (a) : (b))
#define MAX(a, b)	((a) < (b) ? (b) : (a))

#define xrows		(rows - 1)

#define SBUFSZ		128
#define ALIGN(n, a)	(((n) + (a) - 1) & ~((a) - 1))
#define NEXTSZ(o, r)	ALIGN(MAX((o) * 2, (o) + (r)), SBUFSZ)

struct sbuf {
	char *mem;
	size_t len;
	size_t size;
};

struct mail {
	char *file;
	char *scan;
	long idx;
	long depth;
};

static char *mscan_argv[] = {
	"mscan", "-f", "%u%r %10d %17f %t %2i%s",
	(char *)0,
};

static char *print_argv[] = {
	"mshow",
	(char *)0,
};

struct mail *mails;
ssize_t mailalloc = 1024;

static struct termios termios;

static struct sbuf *term_sbuf;
static int cols;
static int rows;

static int xrow;
static int xtop;

static int nlen;

static char vi_msg[512];

static int vi_arg1, vi_arg2;

int idx;

static int quit = 0;
static int printed = 0;

static void
sbuf_extend(struct sbuf *sb, int newsz)
{
	sb->size = newsz;
	sb->mem = realloc(sb->mem, newsz);
}

struct sbuf *
sbuf_make()
{
	struct sbuf *sb = malloc(sizeof(*sb));
	memset(sb, 0, sizeof(*sb));
	return sb;
}

char
*sbuf_buf(struct sbuf *sb)
{
	if (!sb->mem)
		sbuf_extend(sb, 1);
	sb->mem[sb->len] = '\0';
	return sb->mem;
}

size_t
sbuf_done(struct sbuf *sb, char **dest)
{
	size_t len = sb->len;
	*dest = sbuf_buf(sb);
	free(sb);
	return len;
}

void
sbuf_chr(struct sbuf *sb, int c)
{
	if (sb->len + 2 >= sb->size)
		sbuf_extend(sb, NEXTSZ(sb->size, 1));
	sb->mem[sb->len++] = c;
}

void
sbuf_mem(struct sbuf *sb, char *src, size_t len)
{
	if (sb->len + len + 1 >= sb->size)
		sbuf_extend(sb, NEXTSZ(sb->size, len + 1));
	memcpy(sb->mem + sb->len, src, len);
	sb->len += len;
}

void
sbuf_str(struct sbuf *sb, char *src)
{
	sbuf_mem(sb, src, strlen(src));
}

size_t
sbuf_len(struct sbuf *sb)
{
	return sb->len;
}

void
sbuf_free(struct sbuf *sb)
{
	free(sb->mem);
	free(sb);
}

void
add(char *file)
{
	if (idx >= mailalloc) {
		mailalloc *= 2;
		if (mailalloc < 0)
			exit(-1);
		mails = realloc(mails, sizeof (struct mail) * mailalloc);
		if (!mails)
			exit(-1);
		memset(mails+mailalloc/2, 0, sizeof (struct mail) * mailalloc/2);
	}
	if (!mails)
		exit(-1);

	char *s = file;
	while (*s && *s == ' ')
		s++;
	mails[idx].file = strdup(file);
	mails[idx].idx = idx;
	mails[idx].depth = s-file;
	idx++;
}

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

/*
void
seq_to_nl()
{
	if (inlen == 0) {
		char *s = mails[oidx++].file;
		inlen = strlen(s);
		if (inlen + 512 > inalloc) {
			inalloc *= 2;
			if (inalloc < 0)
				exit(-1);
			input = realloc(input, inalloc);
			if (!input)
				exit(-1);
		}
		memcpy(input, s, inlen);
		input[inlen++] = '\n';
		input[inlen] = '\0';
		inpos = input;
	}
}
*/

int
cmd_pipe(char *argv[],
    char *input, size_t inlen,
    char **output, size_t *outlen,
    char **error, size_t *errlen)
{
	char buf[512];
	struct sbuf *obuf, *ebuf;
	sigset_t mask, orig_mask;
	pid_t pid;
	int ifd = -1, ofd = -1, efd = -1;
	int r = 0;

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
				sbuf_mem(obuf, buf, ret);
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
				sbuf_mem(ebuf, buf, sizeof (buf));
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


int
term_read(void)
{
	struct pollfd ufds[1];
	int n;
	char c[1];

	ufds[0].fd = 0;
	ufds[0].events = POLLIN;
	if (poll(ufds, 1, -1) <= 0)
		return -1;
	if ((n = read(0, c, 1)) <= 0)
		return -1;
	return *c;
}

static void
term_str(char *s)
{
	if (term_sbuf)
		sbuf_str(term_sbuf, s);
	else
		while (write(1, s, strlen(s)) < 0 && errno == EAGAIN)
			;
}

static void
term_kill()
{
	term_str("\33[K");
}

void
term_room(int n)
{
	char cmd[16];
	if (n < 0)
		sprintf(cmd, "\33[%dM", -n);
	if (n > 0)
		sprintf(cmd, "\33[%dL", n);
	if (n)
		term_str(cmd);
}

void
term_pos(int r, int c)
{
	char buf[32] = "\r";
	if (c < 0)
		c = 0;
	if (c >= cols - 1)
		c = cols - 1;
	if (r < 0)
		sprintf(buf, "\r\33[%d%c", abs(c), c > 0 ? 'C' : 'D');
	else
		sprintf(buf, "\33[%d;%dH", r + 1, c + 1);
	term_str(buf);
}

void
term_init()
{
	struct winsize w;
	struct termios newtermios;

	tcgetattr(0, &termios);
	newtermios = termios;
	newtermios.c_lflag &= ~(ICANON | ISIG);
	newtermios.c_lflag &= ~ECHO;
	tcsetattr(0, TCSAFLUSH, &newtermios);

	if (getenv("LINES"))
		rows = atoi(getenv("LINES"));
	if (getenv("COLUMNS"))
		cols = atoi(getenv("COLUMNS"));
	if (ioctl(1, TIOCGWINSZ, &w) == 0) {
		cols = w.ws_col;
		rows = w.ws_row;
	}

	cols = cols ? cols : 80;
	rows = rows ? rows : 25;

	term_str("\33[m");

	char str[128];
	sprintf(str, "%d", cols);
	setenv("COLUMNS", str, 0);
	sprintf(str, "%d", rows);
	setenv("LINES", str, 0);
}
void
term_done()
{
	tcsetattr(0, 0, &termios);
}

void
term_suspend()
{
	term_done();
	kill(getpid(), SIGSTOP);
	term_init();
}

void
term_record()
{
	if (!term_sbuf)
		term_sbuf = sbuf_make();
}

void
term_commit()
{
	if (term_sbuf) {
		char *s = sbuf_buf(term_sbuf);
		size_t l = sbuf_len(term_sbuf);
		while (write(1, s, l) < 0 && errno == EAGAIN)
			;
		sbuf_free(term_sbuf);
		term_sbuf = 0;
	}
}

static int vi_buf[128];
static size_t vi_buflen;

static int
vi_read(void)
{
	return vi_buflen ? vi_buf[--vi_buflen] : term_read();
}

static void
vi_back(int c)
{
	if (vi_buflen < sizeof(vi_buf))
		vi_buf[vi_buflen++] = c;
}


static char *
vi_prompt(char *msg, int *kbmap)
{
	int c;
	int cmd_len;
	int cmd_max;
	char *cmd;
	char *p;
	int pos = strlen(msg);

	cmd_max = 1024;
	cmd = malloc(cmd_max);
	if (!cmd)
		exit(1);

	c = 0;
	cmd_len = 0;
	*cmd = 0;

	term_pos(xrows, 0);
	term_kill();
	term_str(msg);

	while (1) {
		term_pos(rows - 1, pos);
		term_kill();
		term_str(cmd);
		c = term_read();
		switch (c) {
		case TK_CTL('h'):
		case 127:
			if (cmd_len > 0)
				cmd[--cmd_len] = '\0';
			break;
		case TK_CTL('u'):
			cmd[0] = '\0';
			cmd_len = 0;
			break;
		case TK_CTL('w'):
			for (p = cmd+cmd_len-1; p >= cmd && *p == ' '; p--)
				*p = '\0';
			if ((p = strrchr(cmd, ' ')))
				cmd_len = p-cmd+1;
			else
				cmd_len = 0;
			cmd[cmd_len] = '\0';
			break;
		default:
			if (c == '\n' || TK_INT(c))
				break;
			cmd[cmd_len++] = c;
			cmd[cmd_len] = '\0';
			break;
		}
		if (c == '\n' || TK_INT(c))
			break;
	}

	if (c == '\n')
		return cmd;

	free(cmd);
	return 0;
}

/* show an ex message */
void ex_show(char *msg)
{
	snprintf(vi_msg, sizeof(vi_msg), "%s", msg);
}

#define EXLEN	512

static int ex_lineno(char **num)
{
	int n = xrow;
	switch ((unsigned char) **num) {
	case '.':
		*num += 1;
		break;
	case '$':
		n = idx - 1;
		*num += 1;
		break;
	case '\'':
		/* if (lbuf_jump(xb, (unsigned char) *++(*num), &n, NULL)) */
		/* 	return -1; */
		*num += 1;
		break;
	case '/':
	case '?':
		/* n = ex_search(num); */
		break;
	default:
		if (isdigit((unsigned char) **num)) {
			n = atoi(*num) - 1;
			while (isdigit((unsigned char) **num))
				*num += 1;
		}
	}
	while (**num == '-' || **num == '+') {
		n += atoi((*num)++);
		while (isdigit((unsigned char) **num))
			(*num)++;
	}
	return n;
}

static int
ex_region(char *loc, int *beg, int *end)
{
	int naddr = 0;
	if (!strcmp("%", loc)) {
		*beg = 0;
		*end = MAX(0, idx);
		return 0;
	}
	if (!*loc) {
		*beg = xrow;
		*end = xrow == idx ? xrow : xrow + 1;
		return 0;
	}
	while (*loc) {
		int end0 = *end;
		*end = ex_lineno(&loc) + 1;
		*beg = naddr++ ? end0 - 1 : *end - 1;
		if (!naddr++)
			*beg = *end - 1;
		while (*loc && *loc != ';' && *loc != ',')
			loc++;
		if (!*loc)
			break;
		if (*loc == ';')
			xrow = *end - 1;
		loc++;
	}
	if (*beg < 0 || *beg >= idx)
		return 1;
	if (*end < *beg || *end > idx)
		return 1;
	return 0;
}

static char *
ex_loc(char *s, char *loc)
{
	while (*s == ':' || isspace((unsigned char) *s))
		s++;
	while (*s && !isalpha((unsigned char) *s) && *s != '=' && *s != '!') {
		if (*s == '\'')
			*loc++ = *s++;
		if (*s == '/' || *s == '?') {
			int d = *s;
			*loc++ = *s++;
			while (*s && *s != d) {
				if (*s =='\\' && s[1])
					*loc++ = *s++;
				*loc++ = *s++;
			}
		}
		if (*s)
			*loc++ = *s++;
	}
	*loc = '\0';
	return s;
}

static char * ex_cmd(char *, char *);

/* read ex command argument */
static char *
ex_arg(char *s, char *arg)
{
	s = ex_cmd(s, arg);
	while (isspace((unsigned char) *s))
		s++;
	while (*s && !isspace((unsigned char) *s)) {
		if (*s == '\\' && s[1])
			s++;
		*arg++ = *s++;
	}
	*arg = '\0';
	return s;
}

static char *
ex_argeol(char *ec)
{
	char arg[EXLEN];
	char *s = ex_cmd(ec, arg);
	while (isspace((unsigned char) *s))
		s++;
	return s;
}

static int
ec_quit(char *ec)
{
	(void) ec;
	/* char cmd[EXLEN]; */
	/* ex_cmd(ec, cmd); */
	/* if (!strchr(cmd, '!')) */
	/* 	if (ex_modifiedbuffer("buffer modified\n")) */
	/* 		return 1; */
	quit = 1;
	return 0;
}

static int ex_expand(char *d, char *s)
{
	while (*s) {
		int c = (unsigned char) *s++;
		if (c == '%') {
			/* if (!bufs[0].path || !bufs[0].path[0]) { */
			/* 	ex_show("\"%\" is unset\n"); */
			/* 	return 1; */
			/* } */
			/* strcpy(d, bufs[0].path); */
			/* d = strchr(d, '\0'); */
			continue;
		}
		if (c == '#') {
			/* if (!bufs[1].path || !bufs[1].path[0]) { */
			/* 	ex_show("\"#\" is unset\n"); */
			/* 	return 1; */
			/* } */
			/* strcpy(d, bufs[1].path); */
			/* d = strchr(d, '\0'); */
			continue;
		}
		if (c == '\\' && (*s == '%' || *s == '#'))
			c = *s++;
		*d++ = c;
	}
	*d = '\0';
	return 0;
}

static int
ec_linenum(char *cmd)
{
	(void) cmd;
	snprintf(vi_msg, sizeof(vi_msg), "%d", xrow+1);
	return 0;
}

static int
ec_exec(char *cmd)
{
	int r;

	/* fprintf(stderr, "ec_)exec cmd=%s\n", cmd); */

	cmd++;

	term_pos(xrows, 0);
	term_str("\n");
	
	r = cmd_pipesh(cmd, 0, 0, 0, 0, 0, 0);
	printed++;
	return r;
}


static int
ec_read(char *ec)
{
	char arg[EXLEN], loc[EXLEN];
	char msg[128];
	int beg, end;
	char *path;
	char *obuf;
	size_t olen;
	int n = idx;
	ex_arg(ec, arg);
	ex_loc(ec, loc);
	/* path = arg[0] ? arg : ex_path(); */
	if (ex_region(loc, &beg, &end))
		return 1;
	if (arg[0] == '!') {
		int pos = MIN(xrow + 1, idx);
		if (ex_expand(arg, ex_argeol(ec)))
			return 1;
		cmd_pipesh(arg + 1, 0, 0, &obuf, &olen, 0, 0);
		/* if (obuf) */
		/* 	lbuf_edit(xb, obuf, pos, pos); */
		free(obuf);
	} else {
		int fd = open(path, O_RDONLY);
		int pos = idx ? end : 0;
		if (fd < 0) {
			ex_show("read failed\n");
			return 1;
		}
		/* if (lbuf_rd(xb, fd, pos, pos)) { */
		/* 	ex_show("read failed\n"); */
		/* 	close(fd); */
		/* 	return 1; */
		/* } */
		close(fd);
	}
	xrow = end + idx - n - 1;
	snprintf(msg, sizeof(msg), "\"%s\"  %d lines  [r]\n",
			path, idx - n);
	ex_show(msg);
	return 0;
}

static int
ec_glob(char *cmd)
{
	return 0;
}

static int
ec_null(char *cmd)
{
	return 0;
}

static struct excmd {
	char *abbr;
	char *name;
	int (*ec)(char *s);
} excmds[] = {
	{ "q", "quit", ec_quit },
	{ "q!", "quit!", ec_quit },
	{ "r", "read", ec_read },
	{ "v", "vglobal", ec_glob},
	{ "=", "=", ec_linenum },
	{ "!", "!", ec_exec },
	{ "", "", ec_null },
};

static char *
ex_cmd(char *s, char *cmd)
{
	char *cmd0 = cmd;
	s = ex_loc(s, cmd);
	while (isspace((unsigned char) *s))
		s++;
	while (isalpha((unsigned char) *s))
		if ((*cmd++ = *s++) == 'k' && cmd == cmd0 + 1)
			break;
	if (*s == '!' || *s == '=')
		*cmd++ = *s++;
	*cmd = '\0';
	return s;
}


static void
ex_line(int (*ec)(char *s), char *dst, char **src)
{
	if (!ec || ec != ec_glob) {
		while (**src && **src != '|' && **src != '\n')
			*dst++ = *(*src)++;
		*dst = '\0';
		if (**src)
			(*src)++;
	} else {
		strcpy(dst, *src);
		*src = strchr(*src, '\0');
	}
}

static int
ex_exec(char *ln)
{
	char ec[EXLEN];
	char cmd[EXLEN];
	size_t i;
	int ret = 0;

	while (*ln) {
		ex_cmd(ln, cmd);
		for (i = 0; i < LEN(excmds); i++) {
			if (!strcmp(excmds[i].abbr, cmd) ||
			    !strcmp(excmds[i].name, cmd)) {
				ex_line(excmds[i].ec, ec, &ln);
				ret = excmds[i].ec(ec); // XXX: pass cmd
				break;
			}
		}
	}

	return ret;
}

void
ex_command(char *ln)
{
	ex_exec(ln);
	// reg_put(':', ln, 0);
}

// XXX: leaking on exit, dont care at the moment
static regex_t pattern;
static char *search_kwd;
static int search_dir;

static int
vi_search(int cmd, int cnt, int *row, int *off)
{
	int i, j, dir;
	int res = *row;

	if (cmd == '/' || cmd == '?') {
		char sign[2] = { cmd, 0 };
		char *kw = vi_prompt(sign, 0);
		if (!kw)
			return 1;
		regfree(&pattern);
		int r = regcomp(&pattern, kw, REG_EXTENDED|REG_ICASE);
		if (r != 0) {
			char buf[256];
			regerror(r, &pattern, buf, sizeof buf);
			snprintf(vi_msg, sizeof(vi_msg), "%s: \"%s\"", buf, kw);
			return 1;
		}
		free(search_kwd);
		search_kwd = strdup(kw);
		free(kw);
		search_dir = cmd == '/' ? +1 : -1;
		res = 0;
	} else if (!search_kwd) {
		return 1;
	}

	dir = cmd == 'N' ? -search_dir : search_dir;
	for (i = 0; i < cnt; i++) {
		for (j = res ? res : *row; j >= 0 && j < idx; j += dir)
			if (regexec(&pattern, mails[j].scan, 0, 0, 0) == 0)
				if (j != res) {
					res = j;
					break;
				}
		// if the first round has no results dont run again
		if (!res) break;
	}

	if (res) {
		*row = res;
		return 0;
	}
		
	snprintf(vi_msg, sizeof(vi_msg), "\"%s\" not found", search_kwd);
	return 1;
}

int
scan(int r1, int r2)
{
	int i;
	struct sbuf *ibuf = sbuf_make();
	char *input, *output, *error;
	size_t inlen, outlen, errlen;

	for (i = r1; i <= r2 && i < idx; i++) {
		sbuf_str(ibuf, mails[i].file);
		sbuf_chr(ibuf, '\n');
	}
	
	inlen = sbuf_done(ibuf, &input);
	cmd_pipe(mscan_argv, input, inlen, &output, &outlen, &error, &errlen);

	i = r1;
	char *p = output, *d;
	while (p < output+outlen && (d = strchr(p, '\n'))) {
		*d = '\0';
		mails[i++].scan = strdup(p);
		fprintf(stderr, "> %s\n", p);
		p = d+1;
	}

	return 0;
}

static int
vi_motionln(int *row, int cmd)
{
	int cnt = (vi_arg1 ? vi_arg1 : 1) * (vi_arg2 ? vi_arg2 : 1);
	int c = vi_read();
	switch (c) {
	case '+':
	case '\n':
	case 'j':
		*row = MIN(*row + cnt, idx - 1);
		break;
	case '-':
	case 'k':
		*row = MAX(*row - cnt, 0);
		break;
	case 'G':
		*row = (vi_arg1 || vi_arg2) ? cnt - 1 : idx - 1;
		break;
	default:
		if (c == cmd) {
			 *row = MIN(*row + cnt - 1, idx - 1);
			 break;
		}
		vi_back(c);
		return 0;
	}
	return c;
}

static int
vi_motion(int *row, int *off)
{
	int cnt = (vi_arg1 ? vi_arg1 : 1) * (vi_arg2 ? vi_arg2 : 1);
	int i, j;
	int mv;
	if ((mv = vi_motionln(row, 0))) {
		*off = -1;
		return mv;
	}
	mv = vi_read();
	switch (mv) {
	case '[':
		if (vi_read() != '[')
			return -1;
		for (i = 0; i < cnt; i++) {
			for (j = *row; j >= 0; j--)
				if (mails[*row].depth > mails[j].depth) {
					*row = j > idx ? idx : j;
					break;
				} else if (mails[*row].depth < mails[j].depth) {
					break;
				}
		}
		break;
	case ']':
		if (vi_read() != ']')
			return -1;
		for (i = 0; i < cnt; i++) {
			for (j = *row; j < idx; j++) {
				/* fprintf(stderr, "]: dr=%ld di=%ld\n", mails[*row].depth, mails[i].depth); */
				if (mails[*row].depth < mails[j].depth) {
					*row = j > idx ? idx : j;
					break;
				} else if (mails[*row].depth > mails[j].depth) {
					break;
				}
			}
		}
		break;
	case '{':
		for (i = *row-1; i >= 0; i--)
			if (*mails[i].file != ' ' && --cnt == 0)
				break;
		*row = i == 0 ? 0 : i;
		break;
	case '}':
		for (i = *row+2; i < idx; i++)
			if (*mails[i].file != ' ' && --cnt == 0)
				break;
		*row = i == idx ? idx : i;
		break;
	case '/':
	case '?':
	case 'n':
	case 'N':
		if (vi_search(mv, cnt, row, off))
			return -1;
		break;
	default:
		vi_back(mv);
		return 0;
	}
	return mv;
}

static int
vi_prefix()
{
	int n = 0;
	int c = vi_read();
	if ((c >= '1' && c <= '9')) {
		while (isdigit(c)) {
			n = n * 10 + c - '0';
			c = vi_read();
		}
	}
	vi_back(c);
	return n;
}

void
m_exec(int r1, int r2, char *cmd)
{
	int i;
	struct sbuf *ibuf = sbuf_make();
	char *input;
	size_t inlen;

	term_pos(xrows, 0);
	term_done();

	for (i = r1; i <= r2 && i < idx; i++) {
		sbuf_str(ibuf, mails[i].file);
		sbuf_chr(ibuf, '\n');
	}
	inlen = sbuf_done(ibuf, &input);

	cmd_pipesh(cmd, input, inlen, 0, 0, 0, 0);

	printed++;
	term_init();
}

void
m_pipe(int r1, int r2, char *cmd)
{
	int i;
	struct sbuf *ibuf = sbuf_make();
	char *input, *output, *error;
	size_t inlen, outlen, errlen;

	fprintf(stderr, "mpipe r1=%d r2=%d\n", r1, r2);

	for (i = r1; i <= r2 && i <= idx; i++) {
		sbuf_str(ibuf, mails[i].file);
		sbuf_chr(ibuf, '\n');
	}
	inlen = sbuf_done(ibuf, &input);

	fprintf(stderr, "mpipe >\n %s\n", input);

	cmd_pipesh(cmd, input, inlen, &output, &outlen, 0, 0);

	fprintf(stderr, "mpipe <\n %s\n", output);

	i = r1;
	char *p = output, *d;
	while (p < output+outlen && (d = strchr(p, '\n'))) {
		*d = '\0';
		fprintf(stderr, "old=%s\n", mails[i].file);
		fprintf(stderr, "new=%s\n", p);
		mails[i].file = strdup(p);
		i++;
		p = d+1;
	}
	scan(r1, r2);
}

struct motion {
	char key;
	void (*mc)(int, int, char *);
	char *cmd;
} motions[] = {
	{ 'p', m_exec, "mshow" },
	{ 'd', m_pipe, "./mflag -vS" },
	{ 'u', m_pipe, "./mflag -vs" },
	{ 't', m_pipe, "./mflag -vt" },
	{ 'T', m_pipe, "./mflag -vT" },
};

static int
vc_motion(int cmd)
{
	int mv;
	int r1 = xrow, r2 = xrow;

	vi_arg2 = vi_prefix();
	if (vi_arg2 < 0)
		return 1;

	if ((mv = vi_motionln(&r2, cmd))) {
		//o2 = -1;
	} else if (!(mv = vi_motion(&r2, 0))) {
		vi_read();
		return 1;
	}
	if (mv < 0)
		return 1;

	size_t i;
	for (i = 0; i < LEN(motions); i++)
		if (motions[i].key == cmd) {
			motions[i].mc(r1, r2, motions[i].cmd);
			return 0;
		}

	return 1;
}

void
draw_row(int row)
{
	char *s = 0;
	if (row < idx)
		s = mails[row].scan;

	/* fprintf(stderr, "draw_row row=%d xrow=%d\n", row, xrow); */
	term_pos(row - xtop, 0);
	term_kill();
	if (1 && s) {// draw numbers
		char num[128];
		snprintf(num, 128, "%*d ", nlen, row+1);
		term_str(num);
	}
	if (row == xrow) {
		term_str("\33[0;32m");
	}
	term_str(s ? s : (row ? "~" : ""));
	if (row == xrow) {
		term_str("\33[0m");
	}
}

void
vi_wait()
{
	char c;
	if (printed >= 1) {
		term_pos(xrows, 0);
		term_kill();
		term_str("[enter to continue]");
		while ((c = vi_read()) != '\n' && !TK_INT(c))
			;
	}
	printed = 0;
	vi_msg[0] = '\0';
}

void
vi_drawmsg()
{
	term_pos(xrows, 0);
	term_kill();
	term_str(vi_msg);
	vi_msg[0] = '\0';
}

void
draw_update(int otop)
{
	int i;

	if (otop != xtop) {
		term_record();
		term_pos(0, 0);
		term_room(otop - xtop);

		if (xtop > otop) {
			int n = MIN(xtop - otop, xrows);
			for (i = 0; i < n; i++)
				draw_row(xtop + xrows - n + i);
		} else {
			int n = MIN(otop - xtop, xrows);
			for (i = 0; i < n; i++)
				draw_row(xtop + i);
		}
		term_pos(xrow, 0);
		term_commit();
	}
	vi_drawmsg();
	term_pos(xrow, 0);
}

void
draw_again(int lineonly)
{
	int i;
	term_record();
	for (i = xtop; i < xtop + xrows; i++)
		if (!lineonly || i == xrow)
			draw_row(i);
	vi_drawmsg();
	term_pos(xrow, 0);
	term_commit();
}

static int
vi_scrollforeward(int cnt)
{
	if (xtop >= idx - 1)
		return 1;
	xtop = MIN(idx - 1, xtop + cnt);
	xrow = MAX(xrow, xtop);
	return 0;
}

static int
vi_scrollbackward(int cnt)
{
	if (xtop == 0)
		return 1;
	xtop = MAX(0, xtop - cnt);
	xrow = MIN(xrow, xtop + xrows - 1);
	return 0;
}

int main(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "")) != -1)
		switch(c) {
		default:
			fprintf(stderr,
			    "Usage: mvi\n");
			exit(1);
		}

	mails = calloc(sizeof (struct mail), mailalloc);
	if (!mails)
		exit(-1);

	if (argc == optind && isatty(0))
		blaze822_loop1(":", add);
	else
		blaze822_loop(argc-optind, argv+optind, add);

	term_init();
	scan(0, idx);


	xtop = MAX(0, xrow - xrows / 2);
	nlen = 1;
	for (int l = idx+1; l > 9; l /= 10)
		nlen++;
	draw_again(0);
	term_pos(xrow - xtop, 0);

	char *cmd;
	while (!quit) {
		int mod = 0;
		int mv;
		int otop = xtop;
		int nrow = xrow;
		int orow = xrow;
		int noff = 0;
		vi_arg2 = 0;
		vi_arg1 = vi_prefix();
		mv = vi_motion(&nrow, &noff);
		if (mv > 0) {
			xrow = nrow;
		} else if (mv == 0) {
			char c = vi_read();
			switch (c) {
			case TK_CTL('b'):
				if (vi_scrollbackward(MAX(1, vi_arg1) * (xrows - 1)))
					break;
				break;
			case TK_CTL('f'):
				if (vi_scrollforeward(MAX(1, vi_arg1) * (xrows - 1)))
					break;
				break;
			case TK_CTL('e'):
				if (vi_scrollforeward(MAX(1, vi_arg1)))
					break;
				break;
			case TK_CTL('y'):
				if (vi_scrollbackward(MAX(1, vi_arg1)))
					break;
				break;
			case TK_CTL('z'):
				term_pos(xrows, 0);
				term_suspend();
				mod = 1;
				break;
			case ':':
				cmd = vi_prompt(":", 0);
				if (cmd) {
					ex_command(cmd);
					mod = 1;
				}
				free(cmd);
				if (quit)
					continue;
				break;
			case 'P':
				vi_back('p');
				vc_motion('p');
				mod = 1;
				break;
			default:
				if (TK_INT(c)) {
					// ^[[A -- arrow up
					// ^[[B -- arrow down
					// ^[[5 -- page up
					// ^[[6 -- page down
					if ((c = vi_read()) == '[')
						switch ((c = vi_read())) {
						case 'A': vi_back('k'); continue;
						case 'B': vi_back('j'); continue;
						case '5': vi_back(TK_CTL('b')); continue;
						case '6': vi_back(TK_CTL('f')); continue;
						default: vi_back(c);
						}
					vi_back(c);
					break;
				}
				if (!vc_motion(c))
					mod = 1;
			}
		}
		if (xrow < 0 || xrow >= idx)
			xrow = idx ? idx - 1 : 0;
		if (xtop > xrow)
			xtop = xtop - xrows / 2 > xrow ?
			    MAX(0, xrow - xrows / 2) : xrow;
		if (xtop + xrows <= xrow)
			xtop = xtop + xrows + xrows / 2 <= xrow ?
			    xrow - xrows / 2 : xrow - xrows + 1;
		vi_wait();
		if (mod)
			draw_again(mod == 2);
		if (xtop != otop) {
			draw_update(otop);
		}
		if (orow != xrow) {
			if (orow >= xtop && orow < xtop + xrows) draw_row(orow);
			if (xrow < xtop + xrows) draw_row(xrow);
		}
		if (vi_msg[0])
			vi_drawmsg();
		term_pos(xrow - xtop, 0);
		// blaze822_seq_setcur(mails[xrow].file);
	}

	term_pos(xrows, 0);
	term_kill();
	term_done();


	return 0;
}

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
	long depth;
};

struct exarg {
	int r1;
	int r2;
	char *cmd;
	char *args;
};

struct excmd {
	char *abbr;
	char *name;
	int (*ec)(struct exarg *);
};

ssize_t mailalloc = 1024;
static int num = 0;
struct mail *mails;

static struct termios termios;
static struct sbuf *term_sbuf;
static int cols;
static int rows;
static int mod;

static int xrow;
static int xtop;

static int nlen;

static int quit = 0;
static int printed = 0;

static char vi_msg[512];
static int vi_arg1, vi_arg2;

static char *mscan_argv[] = {
	"mscan", "-f", "%u%r %10d %17f %t %2i%s",
	(char *)0,
};

static int ec_quit(struct exarg *);
static int ec_print(struct exarg *);
static int ec_read(struct exarg *);
static int ec_write(struct exarg *);
static int ec_glob(struct exarg *);
static int ec_linenum(struct exarg *);
static int ec_exec(struct exarg *);
static int ec_null(struct exarg *);

static struct excmd excmds[] = {
	{ "q", "quit", ec_quit },
	{ "q!", "quit!", ec_quit },
	{ "p", "print", ec_print },
	{ "r", "read", ec_read },
	{ "w", "write", ec_write },
	{ "w!", "write!", ec_write },
	{ "v", "vglobal", ec_glob},
	{ "=", "=", ec_linenum },
	{ "!", "!", ec_exec },
	{ "", "", ec_null },
};

enum mapype {
	MAP_FN = 1,
	MAP_EX,
	MAP_CMD,
	MAP_KEY,
	MAP_CHILD,
};

struct keyarg {
	char key[128];
	int pos;
};

struct keynode {
	int t;
	char key;
	union {
		char *cmd;
		int i;
		char *s;
		int (*fn)(struct keyarg *);
		struct keynode *childs;
	};
};

#define MAP_NULL	{ 0 }
#define MAP_CMD(x, y)	{ MAP_CMD, x, {.cmd=(y)} }
#define MAP_FUN(x, y)	{ MAP_FN, x, {.fn=(y)} }
#define MAP_SUB(x, ...)	{ MAP_CHILD, x, {.childs=(struct keynode[]){__VA_ARGS__}} }

static int ui_excmd(struct keyarg *);
static int ui_search(struct keyarg *);
static int ui_null(struct keyarg *);

static int ui_null(struct keyarg *_) { return 1;};

static struct keynode keytree[] = {
	MAP_SUB(TK_ESC,
		// ^[[A -- arrow up
		// ^[[B -- arrow down
		// ^[[5 -- page up
		// ^[[6 -- page down
		MAP_SUB('[',
			MAP_CMD('A', "prev"),
			MAP_CMD('B', "next"),
			MAP_CMD('5', "back"),
			MAP_CMD('6', "forw"),
			{0}
		),
	),
	MAP_CMD('j', "next"),
	MAP_CMD('k', "prev"),
	MAP_FUN(':', ui_excmd),
	MAP_FUN('/', ui_search),
	MAP_FUN('?', ui_search),
	MAP_FUN('n', ui_search),
	MAP_FUN('N', ui_search),
	MAP_FUN(TK_CTL('z'), ui_null),
	MAP_FUN(TK_CTL('b'), ui_null),
	MAP_FUN(TK_CTL('f'), ui_null),
	MAP_FUN(TK_CTL('e'), ui_null),
	MAP_FUN(TK_CTL('y'), ui_null),
	MAP_SUB('o', 
		MAP_CMD('t', "%!mthread"),
		MAP_CMD('T', "%!sed 's/^[ ]*//'"),
		{0}
	),
	MAP_SUB('s',
		MAP_CMD('d', "%!msort -d"),
		MAP_CMD('D', "%!msort -rd"),
		MAP_CMD('s', "%!msort -s"),
		MAP_CMD('S', "%!msort -rs"),
		{0}
	),
	{0}
};

static int m_pipe(int, int, char *);
static int m_exec(int, int, char *);

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

char *
sbuf_pos(struct sbuf *sb)
{
	if (!sb->mem)
		sbuf_extend(sb, 1);
	return sb->mem+sb->len;
}

char *
sbuf_buf(struct sbuf *sb)
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

static void
seq_add(char *file)
{
	char *s;

	if (num >= mailalloc) {
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

	s = file;
	while (*s && *s == ' ')
		s++;
	
	mails[num].file = strdup(file);
	mails[num].depth = s-file;
	num++;
}

static size_t
seq_get(char **dst, int r1, int r2)
{
	int i;
	struct sbuf *ibuf = sbuf_make();

	for (i = r1; i <= r2 && i < num; i++) {
		sbuf_str(ibuf, mails[i].file);
		sbuf_chr(ibuf, '\n');
	}
	return sbuf_done(ibuf, dst);
}

int
seq_next_thread(int i)
{
	int j;
	for (j = i; j < num; j++) {
		/* fprintf(stderr, "]: dr=%ld di=%ld\n", mails[i].depth, mails[i].depth); */
		if (mails[i].depth < mails[j].depth) {
			return j > num ? num : j;
		} else if (mails[i].depth > mails[j].depth) {
			break;
		}
	}
	return 0;
}

int
seq_prev_thread(int i)
{
	int j;
	for (j = i; j >= 0; j--) {
		if (mails[i].depth > mails[j].depth) {
			return j > num ? num : j;
		} else if (mails[i].depth < mails[j].depth) {
			break;
		}
	}
	return 0;
}

int
seq_next_toplevel(int i)
{
	int j;
	for (j = i+2; j < num; j++)
		if (mails[j].depth == 0)
			break;
	return j == num ? num : j;
}

int
seq_prev_toplevel(int i)
{
	int j;
	for (j = i-1; j >= 0; j--)
		if (mails[j].depth == 0)
			break;
	return j == 0 ? 0 : j;
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

static int
ec_quit(struct exarg *arg)
{
	quit = 1;
	return 0;
}

static int
ec_linenum(struct exarg *arg)
{
	snprintf(vi_msg, sizeof(vi_msg), "%d", xrow+1);
	return 0;
}

static int
ec_exec(struct exarg *arg)
{
	int r;

	fprintf(stderr, "ec_exec: cmd=%s args=%s r1=%d r2=%d\n", arg->cmd, arg->args, arg->r1, arg->r2);

	/* term_pos(xrows, 0); */
	/* term_str("\n"); */
	r = m_pipe(arg->r1, arg->r2, arg->args);

	/* printed++; */
	return r;
}

static int
ec_write(struct exarg *arg)
{
	fprintf(stderr, "ec_write: cmd=%s args=%s r1=%d r2=%d\n", arg->cmd, arg->args, arg->r1, arg->r2);
	return 0;
}

static int
ec_read(struct exarg *arg)
{
	return 0;
}

static int
ec_glob(struct exarg *arg)
{
	return 0;
}

static int
ec_null(struct exarg *arg)
{
	return 0;
}

static int
ec_print(struct exarg *arg)
{
	int r1, r2;

	// default to current mail
	r1 = arg->r1 ? arg->r1 : xrow+1;
	r2 = arg->r2 ? arg->r2 : r1;
	// dont allow backwards ranges
	if (r2 - r1 < 0)
		return 1;

	printed++;
	term_pos(xrows, 0);
	term_str("\n");
	for (int i = r1-1; i < r2; i++) {
		term_str(mails[i].file);
		term_str("\n");
	}

	return 0;
}

static size_t
ex_num(char *s, int *r)
{
	char c;
	int n;
	size_t l;
	l = 1;
	n = 0;
	c = *s++;
	fprintf(stderr, "ex_num: c=%c\n", c);
	if (isdigit(c)) {
		while (isdigit(c)) {
			n = n * 10 + c - '0';
			c = *s++;
			l++;
		}
	}
	l--;
	*r = n;
	fprintf(stderr, "ex_num: l=%d n=%d\n", l, n);
	return l;
}

static ssize_t
ex_mmsg(char *s, int *r) 
{
	int n = 0, m = 0;
	char *p;
	p = s;
	while (*p)
		switch (*p) {
		case '.':
			p++;
			n = xrow+1;
			break;
		case '+':
			p++;
			p += ex_num(p, &m);
			if (!m) m = 1;
			n = n ? n+m : xrow+1+m;
			break;
		case '-':
			p++;
			p += ex_num(p, &m);
			if (!m) m = 1;
			n = n ? n-m : xrow+1-m;
			break;
		default:
			p += ex_num(p, &m);
			if (!m) goto ret;
			n += m;
		}
ret:
	*r = n;
	return p-s;
}

static ssize_t
ex_range(char *s, int *r1, int *r2)
{
	char *p = s;
	if (*s == '%') {
		*r1 = 1;
		*r2 = num-1;
		return 1;
	}
	fprintf(stderr, "ex_range1: p=%s\n", p);
	p += ex_mmsg(p, r1);
	fprintf(stderr, "ex_range2: p=%s\n", p);
	if (*p == ':') {
		p++;
		p += ex_mmsg(p, r2);
	}
	fprintf(stderr, "ex_range3: p=%s\n", p);
	return p-s;
}

static int
ex_command(char *s)
{
	char buf[128];
	struct exarg arg;
	size_t i;
	int ret, r1, r2;
	char *p, *p1;

	fprintf(stderr, "ex_command: %s\n", s);

	ret = 1;
	p = s;

	while (1) {
		r1 = r2 = 0;
		p += ex_range(p, &r1, &r2);
		arg.r1 = r1 ? MIN(MAX(r1, 1), num) : 0;
		arg.r2 = r2 ? MIN(MAX(r2, 1), num) : 0;

		fprintf(stderr, "ex_command: %s\n", p);
		p1 = p;
		while (isspace(*p1) || isalpha(*p1))
			p1++;
		if (*p1 == '!')
			p1++;
		if (p1-p > sizeof buf)
			return 1;
		strncpy(buf, p, p1-p);
		arg.cmd = buf;
		arg.args = p1;
		fprintf(stderr, "ex_command: %s\n", buf);

		for (i = 0; i < LEN(excmds); i++) {
			if (!strcmp(excmds[i].abbr, buf) ||
				!strcmp(excmds[i].name, buf)) {
				if ((ret = excmds[i].ec(&arg)))
					goto ret;
				break;
			}
		}
		break;
	}

ret:
	return ret;
}

// XXX: leaking on exit, dont care at the moment
static regex_t pattern;
static char *search_kwd;
static int search_dir;

static int
vi_search(int cmd, int cnt, int *row)
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
		for (j = res ? res : *row; j >= 0 && j < num; j += dir)
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

	for (i = r1; i <= r2 && i < num; i++) {
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
		*row = MIN(*row + cnt, num - 1);
		break;
	case '-':
	case 'k':
		*row = MAX(*row - cnt, 0);
		break;
	case 'G':
		*row = (vi_arg1 || vi_arg2) ? cnt - 1 : num - 1;
		break;
	default:
		if (c == cmd) {
			 *row = MIN(*row + cnt - 1, num - 1);
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
		fprintf(stderr, "hmm\n");
		if (vi_read() != '[')
			return -1;
		for (i = 0; i < cnt; i++) {
			for (j = *row; j >= 0; j--)
				if (mails[*row].depth > mails[j].depth) {
					*row = j > num ? num : j;
					break;
				} else if (mails[*row].depth < mails[j].depth) {
					break;
				}
		}
		break;
	case ']':
		fprintf(stderr, "hmm1\n");
		if (vi_read() != ']')
			return -1;
		for (i = 0; i < cnt; i++) {
			for (j = *row; j < num; j++) {
				/* fprintf(stderr, "]: dr=%ld di=%ld\n", mails[*row].depth, mails[i].depth); */
				if (mails[*row].depth < mails[j].depth) {
					*row = j > num ? num : j;
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
		for (i = *row+2; i < num; i++)
			if (*mails[i].file != ' ' && --cnt == 0)
				break;
		*row = i == num ? num : i;
		break;
	case '/':
	case '?':
	case 'n':
	case 'N':
		if (vi_search(mv, cnt, row))
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

static int
m_exec(int r1, int r2, char *cmd)
{
	int i, r;
	struct sbuf *ibuf = sbuf_make();
	char *input;
	size_t inlen;

	r = 0;

	term_pos(xrows, 0);
	term_done();

	for (i = r1; i <= r2 && i < num; i++) {
		sbuf_str(ibuf, mails[i].file);
		sbuf_chr(ibuf, '\n');
	}
	inlen = sbuf_done(ibuf, &input);

	r = cmd_pipesh(cmd, input, inlen, 0, 0, 0, 0);

	printed++;
	term_init();
	return r;
}

static int
m_pipe(int r1, int r2, char *cmd)
{
	int i, r;
	char *input, *output, *error;
	size_t inlen, outlen, errlen;

	r = 0;

	fprintf(stderr, "mpipe r1=%d r2=%d\n", r1, r2);

	inlen = seq_get(&input, r1, r2);

	fprintf(stderr, "mpipe >\n %s\n", input);

	cmd_pipesh(cmd, input, inlen, &output, &outlen, &error, &errlen);

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
	return r;
}

static int
vc_motion(int c)
{
	int mv;
	int r1 = xrow, r2 = xrow;

	vi_arg2 = vi_prefix();
	if (vi_arg2 < 0)
		return 1;

	if ((mv = vi_motionln(&r2, c))) {
		//o2 = -1;
	} else if (!(mv = vi_motion(&r2, 0))) {
		/* vi_read(); */
		return 1;
	}
	if (mv < 0)
		return 1;

	return 1;
}

void
draw_row(int row)
{
	char *s = 0;
	if (row < num)
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
	if (s) {
		int i = strlen(s)+nlen;
		if (i > cols) {
			char *st = strndup(s, i-nlen);
			term_str(st);
			free(st);
		} else {
			term_str(s);
		}
	} else {
		term_str("~");
	}
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
	if (xtop >= num - 1)
		return 1;
	xtop = MIN(num - 1, xtop + cnt);
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

static int
ui_excmd(struct keyarg *arg)
{
	char *cmd;
	int r;
	r = 1;
	mod = 1;
	cmd = vi_prompt(":", 0);
	if (cmd)
		r = ex_command(cmd);
	free(cmd);
	return r;
}

static int
ui_search(struct keyarg *arg)
{
	int cnt = (vi_arg1 ? vi_arg1 : 1) * (vi_arg2 ? vi_arg2 : 1);
	if (vi_search(*arg->key, cnt, xrow-1))
		return 1; 
	return 0;
}

static int
match_tree(struct keynode *node, struct keyarg *arg)
{
	size_t i;
	int c = vi_read();
	arg->key[arg->pos++] = c;
	if (TK_INT(c)) {
		return match_tree(keytree[0].childs, arg);
	}
	fprintf(stderr, "match_tree: c=%d\n",c);
	for (i = 0; ; i++) {
		if (node[i].key == 0) break;
		if (node[i].key != c) continue;
		if (node[i].t == MAP_CHILD) {
			return match_tree(node[i].childs, arg);
		} else {
			fprintf(stderr, "matched: %s\n", node[i].cmd);
			switch (node[i].t) {
			case MAP_CMD:
				return ex_command(node[i].cmd);
			case MAP_FN:
				return node[i].fn(arg);
			}
		}
	}
	/* vi_back(c); */
	return 1;
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
		blaze822_loop1(":", seq_add);
	else
		blaze822_loop(argc-optind, argv+optind, seq_add);

	term_init();
	printf("num=%d\n", num);
	scan(0, num);

	xtop = MAX(0, xrow - xrows / 2);
	nlen = 1;
	for (int l = num+1; l > 9; l /= 10)
		nlen++;
	draw_again(0);
	term_pos(xrow - xtop, 0);

	char *cmd;
	struct keyarg karg;
	while (!quit) {
		mod = 0;
		karg.pos = 0;
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
#if 0
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
#endif
			default:
				vi_back(c);
				if (!match_tree(keytree, &karg))
					break;
				if (!vc_motion(c)) {
					mod = 1;
					break;
				}

			}
		}

		if (xrow < 0 || xrow >= num)
			xrow = num ? num - 1 : 0;
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

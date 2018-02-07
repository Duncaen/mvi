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

struct seq {
	struct mail *mails;
	int num;
};

struct exarg {
	int r1;
	int r2;
	struct seq *sq;
	char *cmd;
	char *args;
};

struct excmd {
	char *abbr;
	char *name;
	int (*ec)(struct exarg *);
};

ssize_t mailalloc = 1024;

static struct seq main_seq;
static struct seq grep_seq;
static struct seq search_seq;
static struct seq *temp_seq;

static struct termios termios;
static struct sbuf *term_sbuf;
static int cols;
static int rows;
static int mod;

static int xrow;
static int xtop;

static int orow;
static int nrow;
static int mv;

static int nlen;

static int quit = 0;
static int printed = 0;

static char vi_msg[512];
static int vi_arg1, vi_arg2;

static char *mscan_argv[] = {
	"mscan", "-f", "%u%r %10d %17f %t %2i%s",
	(char *)0,
};

static struct mark {
	int num;
} marks[26*2];

static int ec_exec(struct exarg *);
static int ec_glob(struct exarg *);
static int ec_grep(struct exarg *);
static int ec_linenum(struct exarg *);
static int ec_mark(struct exarg *);
static int ec_null(struct exarg *);
static int ec_print(struct exarg *);
static int ec_quit(struct exarg *);
static int ec_read(struct exarg *);
static int ec_write(struct exarg *);
static int ec_exit(struct exarg *);

static struct excmd excmds[] = {
	{ "q", "quit", ec_quit },
	{ "q!", "quit!", ec_quit },
	{ "p", "print", ec_print },
	{ "r", "read", ec_read },
	{ "w", "write", ec_write },
	{ "w!", "write!", ec_write },
	{ "v", "vglobal", ec_glob },
	{ "g", "global", ec_glob },
	{ "x", "exit", ec_exit },
	{ "ma", "mark", ec_mark },
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

enum {
	SEARCH_UP = 1<<0,
	SEARCH_DOWN = 1<<1,
	SEARCH_PROMPT = 1<<2,
};
enum {
	SCROLL_UP,
	SCROLL_DOWN,
	SCROLL_PAGE_UP,
	SCROLL_PAGE_DOWN,
};

enum keystate {
	KEY_MOTION = 1,
	KEY_OP,
};

typedef struct keynode KeyNode;
typedef struct keyarg KeyArg;

struct keynode {
	int t;
	char key;
	int op;
	union {
		char *cmd;
		int i;
		char *s;
		struct {
			int (*fn)(KeyArg *, void *);
			union {
				int i;
			} arg;
		};
		KeyNode *childs;
	};
};

struct keyarg {
	char key[128];
	int pos;
	int state;
	KeyNode *opnode;
};

#define MAP_NULL	{ 0,0,0,{0} }
#define MAP_CMD(x, y, z)	{ MAP_CMD, x, y, {.cmd=(z)} }
#define MAP_FUN(x, y, z, a)	{ MAP_FN, x, y, {.fn=(z),a } }
#define MAP_SUB(x, ...)	{ MAP_CHILD, x, 0, {.childs=(KeyNode[]){__VA_ARGS__}} }

static int ui_excmd(KeyArg *, void *);
static int ui_search(KeyArg *, void *);
static int ui_scroll(KeyArg *, void *);
static int ui_suspend(KeyArg *, void *);
static int ui_jumpmark(KeyArg *, void *);
static int ui_mark(KeyArg *, void *);
static int ui_move(KeyArg *, void *);

static KeyNode keytree[] = {
	MAP_SUB(TK_ESC,
		// ^[[A -- arrow up
		// ^[[B -- arrow down
		// ^[[5 -- page up
		// ^[[6 -- page down
		MAP_SUB('[',
			MAP_CMD('A', 0, "-"),
			MAP_CMD('B', 0, "+"),
			MAP_CMD('5', 0, "back"),
			MAP_CMD('6', 0, "forw"),
			MAP_NULL
		),
	),
	MAP_CMD('^', KEY_MOTION, "^"),
	MAP_CMD('_', KEY_MOTION, "_"),
	MAP_CMD('p', KEY_OP, "w !mshow"),
	MAP_CMD('d', KEY_OP, "!mflag -vS"),
	MAP_CMD('u', KEY_OP, "!mflag -vs"),
	MAP_CMD('t', KEY_OP, "!mflag -vt"),
	MAP_CMD('T', KEY_OP, "!mflag -vT"),
	MAP_CMD('j', KEY_MOTION, "+"),
	MAP_CMD('k', KEY_MOTION, "-"),
	MAP_FUN('G', KEY_MOTION, ui_move, -1),
	MAP_SUB('g',
		MAP_FUN('g', KEY_MOTION, ui_move, 0),
		MAP_NULL
	),
	MAP_CMD(TK_CTL('n'), KEY_MOTION, "+"),
	MAP_CMD(TK_CTL('p'), KEY_MOTION, "-"),
	MAP_FUN(':', 0, ui_excmd, {0}),
	MAP_FUN('/', KEY_MOTION, ui_search, {.i=SEARCH_PROMPT|SEARCH_DOWN}),
	MAP_FUN('?', KEY_MOTION, ui_search, {.i=SEARCH_PROMPT|SEARCH_UP}),
	MAP_FUN('n', KEY_MOTION, ui_search, {.i=SEARCH_DOWN}),
	MAP_FUN('N', KEY_MOTION, ui_search, {.i=SEARCH_UP}),
	MAP_FUN('m', 0, ui_mark, {0}),
	MAP_FUN('`', KEY_MOTION, ui_jumpmark, {0}),
	MAP_FUN('\'', KEY_MOTION, ui_jumpmark, {0}),
	MAP_FUN(TK_CTL('z'), 0, ui_suspend, {0}),
	MAP_FUN(TK_CTL('b'), 0, ui_scroll, {.i=SCROLL_PAGE_UP}),
	MAP_FUN(TK_CTL('f'), 0, ui_scroll, {.i=SCROLL_PAGE_DOWN}),
	MAP_FUN(TK_CTL('e'), 0, ui_scroll, {.i=SCROLL_DOWN}),
	MAP_FUN(TK_CTL('y'), 0, ui_scroll, {.i=SCROLL_UP}),
	MAP_SUB('o', 
		MAP_CMD('t', 0, "%!mthread"),
		MAP_CMD('T', 0, "%!sed 's/^[ ]*//'"),
		MAP_NULL
	),
	MAP_SUB('s',
		MAP_CMD('d', 0, "%!msort -d"),
		MAP_CMD('D', 0, "%!msort -rd"),
		MAP_CMD('s', 0, "%!msort -s"),
		MAP_CMD('S', 0, "%!msort -rs"),
		MAP_NULL
	),
	MAP_SUB('Z',
		MAP_CMD('Z', 0, "x"),
		MAP_NULL
	),
	MAP_NULL
};

static int m_pipe(int, int, char *, struct seq *);
static int m_exec(int, int, char *, struct seq *);

static int cmd_pipe(char *[], char *, size_t, char **, size_t *, char **, size_t *);
static int cmd_pipesh(char *, char *, size_t, char **, size_t *, char **, size_t *);

static int ex_command(char *, struct seq *);

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
addcb(char *file)
{
	char *s;

	if (temp_seq->num >= mailalloc) {
		mailalloc *= 2;
		if (mailalloc < 0)
			exit(-1);
		temp_seq->mails = realloc(temp_seq->mails, sizeof (struct mail) * mailalloc);
		if (!temp_seq->mails)
			exit(-1);
		memset(temp_seq->mails+mailalloc/2, 0, sizeof (struct mail) * mailalloc/2);
	}

	if (!temp_seq->mails)
		exit(-1);

	s = file;
	while (*s && *s == ' ')
		s++;
	
	temp_seq->mails[temp_seq->num].file = strdup(file);
	temp_seq->mails[temp_seq->num].depth = s-file;
	temp_seq->num++;
}

static void
seq_free(struct seq *sq)
{
	int i;
	for (i = 0; i < sq->num; i++) {
		free(sq->mails[i].file);
	}
}

static void
seq_read(struct seq *sq, int argc, char *argv[])
{
	temp_seq = sq;

	if (!sq->mails)
		if (!(sq->mails = calloc(sizeof (struct mail), mailalloc)))
			exit(-1);

	if (argc == 0)
		blaze822_loop1(":", addcb);
	else
		blaze822_loop(argc, argv, addcb);
}

static void
seq_collect(struct seq *sq, char *buf, ssize_t len)
{
	temp_seq = sq;
	if (!sq->mails)
		if (!(sq->mails = calloc(sizeof (struct mail), mailalloc)))
			exit(-1);

	char *p = buf, *d;
	while (p < buf+len && (d = strchr(p, '\n'))) {
		*d = '\0';
		addcb(p);
		fprintf(stderr, "seq_collect: %s\n", p);
		p = d+1;
	}
}

static struct mail *
seq_get(struct seq *sq, int i)
{
	if (--i > sq->num || i < 0)
		return 0;
	return &sq->mails[i];
}

static size_t
seq_buf(struct seq *sq, char **dst, int r1, int r2)
{
	int i;
	struct sbuf *ibuf;

	r1 = r1 ? r1-1 : 0;
	r2 = r2 ? r2-1 : sq->num;

	ibuf = sbuf_make();
	for (i = r1; i <= r2 && i < sq->num; i++) {
		sbuf_str(ibuf, sq->mails[i].file);
		sbuf_chr(ibuf, '\n');
	}
	return sbuf_done(ibuf, dst);
}

static int
seq_scan(struct seq *seq, int r1, int r2)
{
	int i;
	char *input, *output, *error;
	size_t inlen, outlen, errlen;

	inlen = seq_buf(&main_seq, &input, r1, r2);
	cmd_pipe(mscan_argv, input, inlen, &output, &outlen, &error, &errlen);

	i = r1 ? r1-1 : 0;

	char *p = output, *d;
	while (p < output+outlen && (d = strchr(p, '\n'))) {
		*d = '\0';
		seq->mails[i++].scan = strdup(p);
		fprintf(stderr, "> %s\n", p);
		p = d+1;
	}

	return 0;
}

static size_t
parsenum(char *s, int *r)
{
	char c;
	int n;
	size_t l;
	l = 1;
	n = 0;
	c = *s++;
	if (isdigit(c)) {
		while (isdigit(c)) {
			n = n * 10 + c - '0';
			c = *s++;
			l++;
		}
	}
	l--;
	*r = n;
	return l;
}

static int
seq_parent(struct seq *sq, int start)
{
	int i, maxdepth;
	struct mail *m;

	i = (start ? start : nrow+1);
	if ((m = seq_get(sq, i)) == 0)
		return;

	maxdepth = m->depth;
	if (maxdepth < 1)
		return start;

	for (; i > 0; i--) {
		if ((m = seq_get(sq, i)) == 0)
			return start;
		if (seq_get(sq, i)->depth < maxdepth)
			break;
	}
	return i;
}

static int
seq_subthread(struct seq *sq, int start)
{
	int i, mindepth;
	struct mail *m;

	i = (start ? start : nrow+1);
	if ((m = seq_get(sq, i)) == 0)
		return start;

	mindepth = m->depth;
	for (i+=1; i <= sq->num; i++) {
		if ((m = seq_get(sq, i)) == 0)
			return start;
		if (m->depth <= mindepth)
			break;
	}
	return i-1;
}

static size_t
seq_mmsg(struct seq *sq, char *s, int *r1, int *r2)
{
	int i, n, m, *r;
	char *p;
	*r1 = 0;
	*r2 = 0;
	n = 0;
	p = s;
	r = r1;
	while (*p)
		switch (*p) {
		case ':':
			p++;
			if (r == r2) goto ret;
			*r = n;
			r = r2;
			n = 0;
			break;
		case '$':
			p++;
			n = sq->num;
			break;
		case '.':
			p++;
			n = nrow+1;
			break;
		case '+':
			p++;
			p += parsenum(p, &m);
			if (!m) m = 1;
			n = n ? n+m : nrow+1+m;
			break;
		case '-':
			p++;
			p += parsenum(p, &m);
			if (!m) m = 1;
			n = n ? n-m : nrow+1-m;
			break;
		case '^':
			p++;
			n = seq_parent(sq, n);
			break;
		case '_':
			p++;
			*r = n;
			r = r2;
			n = seq_subthread(sq, n);
			break;
		case '%':
			p++;
			*r1 = 1;
			r = r2;
			n = sq->num;
			break;
		default:
			if ((i = parsenum(p, &m)) == 0)
				goto ret;
			p += i;
			n += m;
		}
ret:
	*r = n;
	// handle start:stop where stop is empty
	if (r == r2 && n == 0)
		*r2 = sq->num;
	return p-s;
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
term_chr(char c)
{
	if (term_sbuf)
		sbuf_chr(term_sbuf, c);
	else
		while (write(1, &c, 1) < 0 && errno == EAGAIN)
			;
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
	kill(getpid(), SIGTSTP);
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

static void
println(char *pref, char *main, int row)
{
	term_record();
	term_pos(row ? row : -1, 0);
	term_kill();
	if (pref)
		term_str(pref);
	if (main)
		term_str(main);
	term_commit();
}

static char *
prompt(char *msg, int *kbmap)
{
	int c;
	int cmd_len;
	int cmd_max;
	char *cmd;
	char *p;
	int pos = strlen(msg);

	(void)(kbmap);

	cmd_max = 1024;
	cmd = malloc(cmd_max);
	if (!cmd)
		exit(1);

	c = 0;
	cmd_len = 0;
	*cmd = 0;

	term_str(msg);

	while (1) {
		println(msg, cmd, -1);
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

static char *
vi_prompt(char *msg, int *kbmap)
{
	term_pos(xrows, 0);
	term_kill();
	return prompt(msg, kbmap);
}

static char *
ex_prompt(char *msg, int *kbmap)
{
	char *s;
	term_pos(-1, 0);
	term_kill();
	s = prompt(msg, kbmap);
	term_pos(-1, 0);
	if (s)
		term_chr('\n');
	return s;
}

static int
ec_quit(struct exarg *arg)
{
	(void)(arg);
	quit = 1;
	return 0;
}

static int
ec_linenum(struct exarg *arg)
{
	snprintf(vi_msg, sizeof(vi_msg), "%d", xrow+1);
	fprintf(stderr, "ec_linenum: cmd=%s args=%s r1=%d r2=%d\n", arg->cmd, arg->args, arg->r1, arg->r2);
	return 0;
}

static int
ec_exec(struct exarg *arg)
{
	int r;

	fprintf(stderr, "ec_exec: cmd=%s args=%s r1=%d r2=%d\n", arg->cmd, arg->args, arg->r1, arg->r2);

	/* term_pos(xrows, 0); */
	/* term_str("\n"); */
	r = m_pipe(arg->r1, arg->r2, arg->args, arg->sq);
	/* r = m_exec(arg->r1, arg->r2, arg->args, arg->sq); */

	// everything is part of the exec command
	arg->args += strlen(arg->args);

	printed++;
	mod = 1;
	return r;
}

static int
ec_write(struct exarg *arg)
{
	fprintf(stderr, "ec_write: cmd=%s args=%s r1=%d r2=%d\n", arg->cmd, arg->args, arg->r1, arg->r2);
	return 0;
}

static int
ec_exit(struct exarg *arg)
{
	fprintf(stderr, "ec_exit: cmd=%s args=%s r1=%d r2=%d\n", arg->cmd, arg->args, arg->r1, arg->r2);
	ec_write(arg);
	ec_quit(arg);
	return 0;
}

static int
ec_read(struct exarg *arg)
{
	return 0;
}

static size_t
parsepattern(char *dst, size_t n, char *s)
{
	int sep;
	char *p;

	if (strlen(s)+1 > n)
		return -1;

	sep = *s;
	// parse /magrep\/pattern/
	for (p = s+1; *p && *p != sep; p++) {
		if (*p == '\\' && p[1] == sep)
			p++;
		*dst++ = *p;
	}
	// pattern has to end with the initial seperator
	if (*p != sep)
		return -1;
	*dst++ = '\0';

	return p-s;
}

static int
ec_glob(struct exarg *arg)
{
	char buf[1024];
	size_t l;
	int r1, r2;

	fprintf(stderr, "ec_glob: cmd=%s args=%s r1=%d r2=%d\n", arg->cmd, arg->args, arg->r1, arg->r2);

	// default to all mails
	if (!arg->r1 && !arg->r2)
		r1 = 1, r2 = main_seq.num;
	else
		r1 = arg->r1, r2 = arg->r2;
	// dont allow backwards ranges
	if (r2 - r1 < 0)
		return 1;

	if ((l = parsepattern(buf, sizeof buf, arg->args)) < 1)
		return 1;
	fprintf(stderr, "parsepattern: buf=%s l=%d\n", buf, l);

	// skip the pattern for next command
	arg->args += l+1;

	char *input, *output;
	size_t inlen, outlen;

	if ((inlen = seq_buf(&main_seq, &input, r1, r2)) < 0)
		return 1;

	int r;
	char *argv[4];

	r = 0;
	argv[r++] = "magrep";
	if (*arg->cmd == 'v')
		argv[r++] = "-v";
	argv[r++] = buf;
	argv[r++] = (void*)0;

	/* term_pos(xrows, 0); */
	/* term_done(); */
	r = cmd_pipe(argv, input, inlen, &output, &outlen, 0, 0);
	/* printed++; */
	/* term_init(); */
	fprintf(stderr, "ec_glob: r=%d outlen=%d\n", r, outlen);
	seq_collect(&grep_seq, output, outlen);

	arg->sq = &grep_seq;

	return 0;
}

static int
ec_grep(struct exarg *arg)
{
	(void)arg;
	return 0;
}

static int
ec_null(struct exarg *arg)
{
	// no command, do a motion
	nrow = MAX(arg->r1, arg->r2);
	nrow = MAX(MIN(nrow-1, main_seq.num), 0);
	mv = 1;
	return 0;
}

static void
ex_print(char *line)
{
	printed += 1;
	if (line)
		snprintf(vi_msg, sizeof(vi_msg), "%s", line);
	if (line)
		println(0, line, -1);
	term_chr('\n');
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

	int i;
	struct mail *m;
	for (i = r1; i <= r2; i++) {
		if (!(m = seq_get(arg->sq, i)))
			continue;
		ex_print(m->file);
	}
	xrow = r2;

	/* term_pos(xrows-2, 0); */
	/* term_str(output); */
	/* printed += r2-r1+1; */
	/* snprintf(vi_msg, sizeof(vi_msg), "%s", output); */
	/* println(0, output); */

	return 0;
}

static int
markidx(int mark)
{
	if (!isalpha(mark))
		return -1;
	return mark > 'Z' ? mark - 'a' : mark - 'A' + 26;
}

static int
setmark(int c, int pos)
{
	int i;
	if ((i = markidx(c)) < 0)
		return 1;
	marks[i].num = pos;
	return 0;
}

static int
ec_mark(struct exarg *arg)
{
	int r1, r2;

	// default to current mail
	r1 = arg->r1 ? arg->r1 : xrow+1;
	r2 = arg->r2 ? arg->r2 : r1;
	// dont allow backwards ranges
	if (r2 - r1 < 0)
		return 1;

	if (*arg->args == '\0' || arg->args[1] != '\0')
		return 1;

	return setmark(*arg->args, MAX(r1, r2));
}

static int
ex_command(char *s, struct seq *sq)
{
	char buf[128];
	struct exarg arg;
	size_t i, l;
	int ret, r1, r2;
	char *p, *p1;

	fprintf(stderr, "ex_command: %s\n", s);

	arg.sq = sq;
	ret = 1;
	p = s;

	while (1) {
		r1 = r2 = 0;
		p += seq_mmsg(sq, p, &r1, &r2);
		arg.r1 = r1 ? MIN(MAX(r1, 1), sq->num) : 0;
		arg.r2 = r2 ? MIN(MAX(r2, 1), sq->num) : 0;

		// move p1 to the beginning of arguments
		p1 = p;
		while (isalpha(*p1)) p1++;
		if (*p1 == '!' || *p1 == '=')
			p1++;

		// copy command into buffer
		l = p1-p;
		if (l > sizeof buf)
			return 1;
		if (l > 0)
			strncpy(buf, p, l);
		buf[l] = '\0';
		arg.cmd = buf;

		while (isspace(*p1)) p1++;
		arg.args = p1;

		fprintf(stderr, "ex_command: %s args=%s r1=%d r2=%d\n", buf, arg.args, arg.r1, arg.r2);

		for (i = 0; i < LEN(excmds); i++) {
			if (!strcmp(excmds[i].abbr, buf) ||
				!strcmp(excmds[i].name, buf)) {
				if ((ret = excmds[i].ec(&arg)))
					goto ret;
				break;
			}
		}
		if (strlen(arg.args) == 0)
			break;
		p = arg.args;
	}

ret:
	return ret;
}

// XXX: leaking on exit, dont care at the moment
static regex_t pattern;
static char *search_kwd;
static int search_dir;

static int
vi_search(int c, int prompt, int dir, int cnt)
{
#if 0
	int i, j;
	int res = nrow;
	if (prompt) {
		char sign[2] = { c, 0 };
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
		search_dir = dir;
		res = 0;
	} else if (!search_kwd) {
		return 1;
	}

	if (!prompt)
		dir = dir == -1 ? -search_dir : search_dir;
	for (i = 0; i < cnt; i++) {
		for (j = res ? res : nrow; j >= 0 && j < main_seq.num; j += dir)
			if (regexec(&pattern, main_seq.mails[j].scan, 0, 0, 0) == 0)
				if (j != res) {
					res = j;
					break;
				}
		// if the first round has no results dont run again
		if (!res) break;
	}

	if (res) {
		nrow = res;
		mv = 1;
		return 0;
	}
		
	snprintf(vi_msg, sizeof(vi_msg), "\"%s\" not found", search_kwd);
	return 1;
#endif
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
m_exec(int r1, int r2, char *cmd, struct seq *sq)
{
	size_t inlen;
	int r;
	char *input;

	r = 0;

	term_pos(xrows, 0);
	term_done();

	inlen = seq_buf(sq, &input, r1, r2);
	r = cmd_pipesh(cmd, input, inlen, 0, 0, 0, 0);

	printed += 2;
	term_init();
	return r;
}

static int
m_pipe(int r1, int r2, char *cmd, struct seq *sq)
{
	size_t inlen, outlen, errlen;
	int i, r;
	char *input, *output, *error;
	struct mail *m;

	r = 0;

	fprintf(stderr, "mpipe r1=%d r2=%d\n", r1, r2);

	inlen = seq_buf(sq, &input, r1, r2);

	fprintf(stderr, "mpipe >\n %s\n", input);

	r = cmd_pipesh(cmd, input, inlen, &output, &outlen, &error, &errlen);

	fprintf(stderr, "mpipe <\n %s\n", output);

	i = r1;
	char *p = output, *d;
	while (p < output+outlen && (d = strchr(p, '\n'))) {
		*d = '\0';
		if ((m = seq_get(sq, i))) {
			fprintf(stderr, "old=%s\n", m->file);
			fprintf(stderr, "new=%s\n", p);
			free(m->file);
			m->file = strdup(p);
		}
		i++;
		p = d+1;
	}
	seq_scan(sq, r1, r2);
	return r;
}

void
draw_row(int row)
{
	struct mail *m;
	char *s;

	s = 0;
	if ((m = seq_get(&main_seq, row+1)))
		s = m->scan;

	/* fprintf(stderr, "draw_row row=%d xrow=%d\n", row, xrow); */

	term_pos(row - xtop, 0);
	term_kill();
	if (1 && s) {// draw numbers
		char buf[128];
		snprintf(buf, 128, "%*d ", nlen, row+1);
		term_str(buf);
	}
	if (row == xrow) {
		term_str("\33[0;32m");
	}
	if (s) {
		int i = strlen(s)+nlen;
		if (i > cols) {
			char *st = strndup(s, i-nlen-3);
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
	int c;
	if (printed > 1) {
		term_pos(xrows, 0);
		term_kill();
		term_str("[enter to continue]");
		while ((c = vi_read()) != '\n' && !TK_INT(c))
			;
		vi_msg[0] = '\0';
	}
	printed = 0;
}

void
vi_drawmsg()
{
	size_t l;
	fprintf(stderr,"vi_dramsg: printed=%d\n", printed);
	if ((l = strlen(vi_msg)-1) <= 0)
		return;
	if (vi_msg[l] == '\n')
		vi_msg[l] = '\0';
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
	if (xtop >= main_seq.num - 1)
		return 1;
	xtop = MIN(main_seq.num - 1, xtop + cnt);
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
ui_excmd(KeyArg *karg, void *arg)
{
	char *cmd;
	int r;
	(void)karg;
	(void)arg;
	r = 1;
	cmd = vi_prompt(":", 0);
	if (cmd)
		r = ex_command(cmd, &main_seq);
	free(cmd);
	mod = 1;
	return r;
}

static int
ui_search(KeyArg *karg, void *arg)
{
	int cnt = (vi_arg1 ? vi_arg1 : 1) * (vi_arg2 ? vi_arg2 : 1);
	int f = *((int *)arg);
	int prompt = (f&SEARCH_PROMPT);
	int dir = (f&SEARCH_DOWN) ? +1 : -1;
	fprintf(stderr, "ui_search: prompt=%d dir=%d\n", prompt,dir);
	if (vi_search(*karg->key, prompt, dir, cnt))
		return 1; 
	return 0;
}

static int
ui_move(KeyArg *karg, void *arg)
{
	int cnt;
	(void)karg;
	nrow = *((int *)arg);
	mv = 1;
	if (nrow != -1) return 0;
	cnt = (vi_arg1 ? vi_arg1 : 1) * (vi_arg2 ? vi_arg2 : 1);
	nrow = (vi_arg1 || vi_arg2) ? cnt-1 : main_seq.num-1;
	return 0;
}

static int
ui_suspend(KeyArg *karg, void *arg)
{
	(void)karg;
	(void)arg;
	term_pos(xrows, 0);
	term_suspend();
	mod = 1;
	return 0;
}

static int
ui_scroll(KeyArg *karg, void *arg)
{
	int i = *((int *)arg);
	(void)karg;
	switch (i) {
	case SCROLL_PAGE_UP:
		return vi_scrollbackward(MAX(1, vi_arg1) * (xrows - 1));
	case SCROLL_PAGE_DOWN:
		return vi_scrollforeward(MAX(1, vi_arg1) * (xrows - 1));
	case SCROLL_UP:
		return vi_scrollbackward(MAX(1, vi_arg1));
	case SCROLL_DOWN:
		return vi_scrollforeward(MAX(1, vi_arg1));
	}
	return 1;
}

static int
ui_mark(KeyArg *karg, void *arg)
{
	(void)karg;
	(void)arg;
	return setmark(vi_read(), nrow);
}

static int
ui_jumpmark(KeyArg *karg, void *arg)
{
	int i, pos;
	(void)karg;
	(void)arg;
	if ((i = markidx(vi_read())) < 0)
		return 1;
	if ((pos = marks[i].num) < 0) {
		snprintf(vi_msg, sizeof(vi_msg), "Mark not set");
		return 1;
	}
	nrow = pos;
	mv = 1;
	return 0;
}

static int
match_tree(KeyNode *node, KeyArg *arg)
{
	KeyNode *n;
	size_t i;
	int c = vi_read();
	int r, j;
	int r1, r2;
	arg->key[arg->pos++] = c;
	if (TK_INT(c)) {
		return match_tree(keytree[0].childs, arg);
	}
	fprintf(stderr, "match_tree: c=%d\n",c);
	for (i = 0; ; i++) {
		n = &node[i];
		if (n->key == 0) break;
		if (n->key != c) continue;
		if (n->t == MAP_CHILD)
			return match_tree(n->childs, arg);
		if (arg->state == KEY_OP && arg->opnode->key == c) {
			// pressed op key two times
			fprintf(stderr, "match_tree: run op %c on current mail\n", c);
			goto doop;
		}
		if (n->op == KEY_OP) {
			arg->state = KEY_OP;
			arg->opnode = n;
			vi_arg2 = vi_prefix();
			return match_tree(keytree, arg);
		}
		fprintf(stderr, "matched: %c\n", c);
		// XXX: dont repeat every command
		int cnt = (vi_arg1 ? vi_arg1 : 1) * (vi_arg2 ? vi_arg2 : 1);
		fprintf(stderr, "match_tree: cnt=%d\n", cnt);
		switch (n->t) {
		case MAP_CMD:
			for (j = 0; j < cnt; j++)
				if ((r = ex_command(n->cmd, &main_seq)))
					break;
			break;
		case MAP_FN:
			for (j = 0; j < cnt; j++)
				if ((r = n->fn(arg, (void *)&n->arg)))
					break;
			break;
		default:
			return 1;
		}
		if (r) return 1;
		if (arg->state == KEY_OP) {
doop:
			// XXX: add count/prefix
			r1 = r2 = xrow+1;
			if (mv) {
				if (nrow < r1) r1 = nrow+1;
				else r2 = nrow+1;
			}
			n = arg->opnode;
			char buf[1024];
			switch (n->t) {
			case MAP_CMD:
				// XXX: wew range to string just to convert it back, need a better solution
				snprintf(buf, sizeof buf, "%d:%d%s", r1, r2, n->cmd);
				return ex_command(buf, &main_seq);
			case MAP_FN:
				return n->fn(arg, (void *)&n->arg);
			default:
				return 1;
			}
		}
		return 0;
	}
	return 1;
}

static int
vi(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	term_init();
	seq_scan(&main_seq, 0, 0);

	xtop = MAX(0, xrow - xrows / 2);
	nlen = 1;
	for (int l = main_seq.num+1; l > 9; l /= 10)
		nlen++;
	draw_again(0);
	term_pos(xrow - xtop, 0);

	KeyArg karg;
	while (!quit) {
		karg.pos = 0;
		karg.state = 0;
		mv = 0;
		mod = 0;
		int otop = xtop;
		nrow = xrow;
		orow = xrow;
		vi_arg2 = 0;
		vi_arg1 = vi_prefix();

		if (!match_tree(keytree, &karg)) {
			if (mv) xrow = nrow;
			/* mod = 1; */
		}

		if (xrow < 0 || xrow >= main_seq.num)
			xrow = main_seq.num ? main_seq.num - 1 : 0;
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
		// blaze822_seq_setcur(main_seq.mails[xrow].file);
	}

	term_pos(xrows, 0);
	term_kill();
	term_done();
	return 0;
}

static int
ex(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	term_init();
	while (!quit) {
		nrow = xrow;
		orow = xrow;

		char *cmd = ex_prompt(":", 0);
		if (!cmd)
			continue;
		if (ex_command(cmd, &main_seq))
			fprintf(stderr, "ex: err");
		free(cmd);
		if (mv)
			xrow = nrow;
		if (xrow < 0 || xrow >= main_seq.num)
			xrow = main_seq.num ? main_seq.num - 1 : 0;
	}
	term_kill();
	term_done();
	return 0;
}

int
main(int argc, char *argv[])
{
	int c;
	int exmode;

	exmode = 0;

	while ((c = getopt(argc, argv, "ev")) != -1)
		switch(c) {
		case 'e': exmode = 1; break;
		case 'v': exmode = 0; break;
		default:
			fprintf(stderr,
			    "Usage: mex [-ev]\n"
			    "Usage: mvi [-ev]\n");
			exit(1);
		}

	if (argc == optind && isatty(0))
		seq_read(&main_seq, 0, 0);
	else
		seq_read(&main_seq, argc-optind, argv+optind);

	return exmode ? ex(argc, argv) : vi(argc, argv);
}

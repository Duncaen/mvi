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
#include <unistd.h>

#include "mvi.h"

#define TK_CTL(x)	((x) & 037)
#define TK_INT(c)	((c) < 0 || (c) == TK_ESC || (c) == TK_CTL('c'))
#define TK_ESC		(TK_CTL('['))

extern struct seq main_seq;
extern struct seq grep_seq;
extern struct seq search_seq;

extern int mod;

extern int xrow;
static int xtop;

extern int orow;
extern int nrow;
static int mv;

static int nlen;

static int resize = 0;
extern int quit = 0;
extern int printed = 0;

enum {
	OPT_NUMBER = 0x00001,
};
static int opts = OPT_NUMBER;

extern char vi_msg[512];
static int vi_arg1, vi_arg2;

static struct mark {
	int num;
} marks[26*2];

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
	MAP_CMD('P', 0, "w !mshow"),
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
	MAP_CMD('\r', KEY_MOTION, "+"),
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

static int
sig_winch(int signo)
{
	(void) signo;
	resize++;
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

void
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

char *
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
			if (c == '\r' || TK_INT(c))
				break;
			cmd[cmd_len++] = c;
			cmd[cmd_len] = '\0';
			break;
		}
		if (c == '\r' || TK_INT(c))
			break;
	}

	if (c == '\r')
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

#if 0
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
#endif

void
draw_row(unsigned int row)
{
	struct mail *m;
	char *s = NULL;

	if ((m = seq_get(&main_seq, row+1)))
		s = m->scan;

	term_pos(row - xtop, 0);
	term_kill();

	if (row == xrow)
		term_str("\33[0;32m");

	if (s) {
		int maxlen = cols;
		if (opts & OPT_NUMBER) { // draw numbers
			char buf[12];
			size_t len;
			len = snprintf(buf, sizeof buf, "%*u ", nlen, row+1);
			if (len < 0)
				goto err;
			term_strn(buf, len);
			maxlen -= nlen+1;
		}
		term_strn(s, maxlen);
	} else {
		term_chr('~');
	}

err:
	if (row == xrow)
		term_str("\33[0m");
}

void
vi_wait()
{
	int c;
	if (printed > 1) {
		term_pos(xrows, 0);
		term_kill();
		term_str("[enter to continue]");
		while ((c = vi_read()) != '\r' && !TK_INT(c))
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

	signal(SIGWINCH, sig_winch);

	term_init();
	term_raw();
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

		if (resize) {
			term_resize();
			mod = 1;
			resize = 0;
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
	term_default();
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

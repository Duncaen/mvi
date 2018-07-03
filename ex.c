#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "mvi.h"

static struct mark {
	int num;
} marks[26*2];

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
m_exec(int r1, int r2, char *cmd, struct seq *sq)
{
	size_t inlen;
	int r;
	char *input;

	r = 0;

	term_pos(xrows, 0);
	term_default();

	inlen = seq_buf(sq, &input, r1, r2);
	r = cmd_pipesh(cmd, input, inlen, 0, 0, 0, 0);

	printed += 2;
	mod = 1;

	term_raw();

	return r;
}

static int
ec_exec(struct exarg *arg)
{
	int r;

	fprintf(stderr, "ec_exec: cmd=%s args=%s r1=%d r2=%d\n", arg->cmd, arg->args, arg->r1, arg->r2);

	/* r = m_pipe(arg->r1, arg->r2, arg->args, arg->sq); */
	r = m_exec(arg->r1, arg->r2, arg->args, arg->sq);

	// everything is part of the exec command
	arg->args += strlen(arg->args);

	return r;
}

static int
ec_write(struct exarg *arg)
{
	int r1, r2;

	// default to current mail
	r1 = arg->r1 ? arg->r1 : xrow+1;
	r2 = arg->r2 ? arg->r2 : r1;

	fprintf(stderr, "ec_write: cmd=%s args=%s r1=%d r2=%d\n", arg->cmd, arg->args, r1, r2);

	if (arg->args && arg->args[0] == '!' && arg->args[1]) {
		int r;
		r = m_exec(r1, r2, arg->args+1, arg->sq);
		// everything is part of the exec command
		arg->args += strlen(arg->args);
		return r;
	}

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
	(void) arg;
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
	fprintf(stderr, "parsepattern: buf=%s l=%ld\n", buf, l);

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
	fprintf(stderr, "ec_glob: r=%d outlen=%ld\n", r, outlen);
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
	/* mv = 1; */
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

int
markidx(int mark)
{
	if (!isalpha(mark))
		return -1;
	return mark > 'Z' ? mark - 'a' : mark - 'A' + 26;
}

int
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

int
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


int
ex(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	term_init();
	term_raw();
	while (!quit) {
		nrow = xrow;
		orow = xrow;

		char *cmd = ex_prompt(":", 0);
		if (!cmd)
			continue;
		if (ex_command(cmd, &main_seq))
			fprintf(stderr, "ex: err");
		free(cmd);
		/*
		if (mv)
			xrow = nrow;
		*/
		if (xrow < 0 || xrow >= main_seq.num)
			xrow = main_seq.num ? main_seq.num - 1 : 0;
	}
	term_kill();
	term_default();
	return 0;
}

#include <stdio.h>
#include <stdlib.h>

#include "blaze822.h"
#include "mvi.h"

static struct seq *temp_seq;
ssize_t mailalloc = 1024;


static char *mscan_argv[] = {
	"mscan", "-f", "%u%r %10d %17f %t %2i%s",
	(char *)0,
};


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

void
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

void
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

struct mail *
seq_get(struct seq *sq, int i)
{
	if (--i > sq->num || i < 0)
		return 0;
	return &sq->mails[i];
}

size_t
seq_buf(struct seq *sq, char **dst, int r1, int r2)
{
	int i;
	sbuf_t *ibuf;

	r1 = r1 ? r1-1 : 0;
	r2 = r2 ? r2-1 : sq->num;

	ibuf = sbuf_make();
	for (i = r1; i <= r2 && i < sq->num; i++) {
		sbuf_str(ibuf, sq->mails[i].file);
		sbuf_chr(ibuf, '\n');
	}
	return sbuf_done(ibuf, dst);
}

int
seq_scan(struct seq *seq, int r1, int r2)
{
	int i;
	char *input, *output, *error;
	size_t inlen, outlen, errlen;

	inlen = seq_buf(seq, &input, r1, r2);
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

size_t
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

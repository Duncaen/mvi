#include <string.h>
#include <stdlib.h>

#include "mvi.h"

#define SBUFSZ		128
#define ALIGN(n, a)	(((n) + (a) - 1) & ~((a) - 1))
#define NEXTSZ(o, r)	ALIGN(MAX((o) * 2, (o) + (r)), SBUFSZ)

struct sbuf {
	char *mem;
	size_t len;
	size_t size;
};

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

static void
sbuf_mem(struct sbuf *sb, const char *src, size_t len)
{
	if (sb->len + len + 1 >= sb->size)
		sbuf_extend(sb, NEXTSZ(sb->size, len + 1));
	memcpy(sb->mem + sb->len, src, len);
	sb->len += len;
}

void
sbuf_str(struct sbuf *sb, const char *src)
{
	sbuf_mem(sb, src, strlen(src));
}

void
sbuf_strn(struct sbuf *sb, const char *src, size_t n)
{
	sbuf_mem(sb, src, n);
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


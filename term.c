#include <sys/ioctl.h>

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "mvi.h"

static struct termios termdef;
static struct termios termraw;
static struct sbuf *term_sbuf;

int cols;
int rows;

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

void
term_chr(char c)
{
	if (term_sbuf)
		sbuf_chr(term_sbuf, c);
	else
		while (write(1, &c, 1) < 0 && errno == EAGAIN)
			;
}

static void
term_mem(const char *s, size_t n)
{
	if (term_sbuf)
		sbuf_strn(term_sbuf, s, n);
	else
		while (write(1, s, n) < 0 && errno == EAGAIN)
			;
}

void
term_strn(const char *s, size_t max)
{
	size_t len = strlen(s);
	term_mem(s, len > max ? max : len);
}

void
term_str(const char *s)
{
	term_mem(s, strlen(s));
}

void
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
term_resize()
{
	struct winsize w;
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

	char str[12];
	sprintf(str, "%u", cols);
	setenv("COLUMNS", str, 0);
	sprintf(str, "%u", rows);
	setenv("LINES", str, 0);
}

void
term_init()
{
	cols = rows = 0;
	tcgetattr(0, &termdef);
	termraw = termdef;
	termraw.c_iflag &= ~(ICRNL | IXON);
	termraw.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	termraw.c_oflag &= ~(OPOST);
	term_str("\33[m");
	term_resize();
}

void
term_raw()
{
	tcsetattr(0, TCSAFLUSH, &termraw);
}

void
term_default()
{
	tcsetattr(0, 0, &termdef);
}

void
term_suspend()
{
	term_default();
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


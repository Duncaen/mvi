#define LEN(a)		(sizeof(a) / sizeof((a)[0]))
#define MIN(a, b)	((a) < (b) ? (a) : (b))
#define MAX(a, b)	((a) < (b) ? (b) : (a))

#define xrows		(rows - 1)

/* mvi.c */
char *	prompt(char *, int *);
void	println(char *, char *, int);

struct mail {
	char *file;
	char *scan;
	long depth;
};

struct seq {
	struct mail *mails;
	int num;
};

struct seq main_seq;
struct seq grep_seq;
struct seq search_seq;

int quit;
int printed;
int mod;
int nrow;
int xrow;
int orow;

char vi_msg[512];

/* term.c */
void	term_chr(char);
void	term_commit();
void	term_default();
void	term_init();
void	term_kill();
void	term_pos(int, int);
void	term_raw();
int		term_read();
void	term_record();
void	term_resize();
void	term_room(int);
void	term_str(const char *);
void	term_strn(const char *, size_t);
void	term_suspend();

extern int cols;
extern int rows;

/* sbuf.c */
typedef struct sbuf sbuf_t;

char *	sbuf_buf(sbuf_t *);
void	sbuf_chr(sbuf_t *, int);
size_t	sbuf_done(sbuf_t *, char **);
void	sbuf_free(sbuf_t *);
size_t	sbuf_len(sbuf_t *);
sbuf_t *sbuf_make();
void	sbuf_str(sbuf_t *, const char *);
void	sbuf_strn(sbuf_t *, const char *, size_t);

/* ex.c */
int ex(int, char *[]);
int ex_command(char *, struct seq *);
int markidx(int);
int setmark(int, int);

/* cmd.c */
int cmd_pipe(char *[], char *, size_t, char **, size_t *, char **, size_t *);
int cmd_pipesh(char *, char *, size_t, char **, size_t *, char **, size_t *);

/* seq.c */
struct mail *	seq_get(struct seq *, int);
void	seq_read(struct seq *, int, char *[]);
int		seq_scan(struct seq *, int, int);
size_t	seq_buf(struct seq *, char **, int, int);
void	seq_collect(struct seq *, char *, ssize_t);
size_t	seq_mmsg(struct seq *, char *, int *, int *);

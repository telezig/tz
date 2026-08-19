/* Minimal time stub for wasm32-freestanding.
   sqlite3.c includes <time.h> unconditionally; the minimal
   currentTimeFunc (used when SQLITE_OMIT_DATETIME_FUNCS) needs
   time/gmtime/strftime, provided by src/db/wasm_shim.zig. */
#ifndef _TIME_H
#define _TIME_H
#include <stddef.h>
typedef long time_t;
struct tm { int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst; };
extern time_t time(time_t *);
extern struct tm *localtime(const time_t *);
extern struct tm *gmtime(const time_t *);
extern time_t mktime(struct tm *);
extern double difftime(time_t, time_t);
extern char *asctime(const struct tm *);
extern char *ctime(const time_t *);
extern unsigned long strftime(char *, unsigned long, const char *, const struct tm *);
#endif

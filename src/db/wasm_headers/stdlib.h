/* Minimal stdlib stub for wasm32-freestanding.
   Declarations only; the symbols themselves are provided by
   src/db/wasm_shim.zig (malloc family over std.heap.wasm_allocator). */
#ifndef _STDLIB_H
#define _STDLIB_H
#include <stddef.h>
#define NULL ((void*)0)
typedef struct { int quot; int rem; } div_t;
typedef struct { long quot; long rem; } ldiv_t;
extern void *malloc(unsigned long);
extern void *calloc(unsigned long, unsigned long);
extern void *realloc(void *, unsigned long);
extern void free(void *);
extern void abort(void);
extern int atexit(void (*)(void));
extern void exit(int);
extern long strtol(const char *, char **, int);
extern double strtod(const char *, char **);
extern int atoi(const char *);
extern int rand(void);
extern void srand(unsigned);
extern void qsort(void *, unsigned long, unsigned long, int (*)(const void *, const void *));
extern void *bsearch(const void *, const void *, unsigned long, unsigned long, int (*)(const void *, const void *));
extern int abs(int);
extern long labs(long);
extern div_t div(int, int);
extern ldiv_t ldiv(long, long);
#endif

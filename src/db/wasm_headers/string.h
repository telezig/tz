/* Minimal string stub for wasm32-freestanding.
   Declarations only; the symbols themselves are provided by
   src/db/wasm_shim.zig. */
#ifndef _STRING_H
#define _STRING_H
#include <stddef.h>
extern void *memcpy(void *, const void *, unsigned long);
extern void *memmove(void *, const void *, unsigned long);
extern void *memset(void *, int, unsigned long);
extern int memcmp(const void *, const void *, unsigned long);
extern void *memchr(const void *, int, unsigned long);
extern unsigned long strlen(const char *);
extern int strcmp(const char *, const char *);
extern int strncmp(const char *, const char *, unsigned long);
extern char *strchr(const char *, int);
extern char *strrchr(const char *, int);
extern char *strstr(const char *, const char *);
extern char *strncpy(char *, const char *, unsigned long);
extern char *strcpy(char *, const char *);
extern char *strcat(char *, const char *);
extern char *strncat(char *, const char *, unsigned long);
extern char *strdup(const char *);
extern char *strerror(int);
extern unsigned long strspn(const char *, const char *);
extern unsigned long strcspn(const char *, const char *);
#endif

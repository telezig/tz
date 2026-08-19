/* Minimal stdio stub for wasm32-freestanding.
   sqlite3.c only references FILE under SQLITE_MEMDEBUG / SQLITE_DEBUG,
   which are never enabled in the wasm build. */
#ifndef _STDIO_H
#define _STDIO_H
typedef struct _iobuf FILE;
#define stdout ((FILE*)0)
#define stderr ((FILE*)0)
#define stdin  ((FILE*)0)
#define EOF (-1)
#endif

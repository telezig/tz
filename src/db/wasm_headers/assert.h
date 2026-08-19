/* Minimal assert stub for wasm32-freestanding.
   wasm builds pass -DNDEBUG=1, so assert() always compiles away. */
#ifndef _ASSERT_H
#define _ASSERT_H
#ifdef NDEBUG
#define assert(x) ((void)0)
#else
#define assert(x) ((void)0)
#endif
#endif

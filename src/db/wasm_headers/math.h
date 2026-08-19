/* Minimal math stub for wasm32-freestanding.
   Declarations only; the symbols themselves are provided by
   src/db/wasm_shim.zig (FTS5 ranking uses log/pow/sqrt). */
#ifndef _MATH_H
#define _MATH_H
extern double sqrt(double);
extern double pow(double, double);
extern double log(double);
extern double log10(double);
extern double exp(double);
extern double fabs(double);
extern double floor(double);
extern double ceil(double);
extern double fmod(double, double);
extern double sin(double);
extern double cos(double);
extern double tan(double);
extern double atan2(double, double);
extern double atan(double);
extern double asin(double);
extern double acos(double);
extern double ldexp(double, int);
extern double frexp(double, int *);
#endif

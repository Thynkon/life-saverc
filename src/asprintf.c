#include "asprintf.h"
#include <stdio.h>  /* needed for vsnprintf    */
#include <stdlib.h> /* needed for malloc, free */
#include <stdarg.h> /* needed for va_*         */

#ifdef __GNUC__
int vscprintf(const char *format, va_list ap) {
    int retval = 0;
    va_list ap_copy;

    va_copy(ap_copy, ap);
    retval = vsnprintf(NULL, 0, format, ap_copy);
    va_end(ap_copy);

    return retval;
}
#endif

/*
 * asprintf, vasprintf:
 * MSVC does not implement these, thus we implement them here
 * GNU-C-compatible compilers implement these with the same names, thus we
 * don't have to do anything
 */
#ifdef _MSC_VER
int vasprintf(char **strp, const char *format, va_list ap) {
    int len = 0;
    int retval = 0;
    char *std = NULL;

    len = vscprintf(format, ap);
    if (len == -1) {
        return -1;
	}

    str = (char*) malloc((size_t) len + 1);
    if (str == NULL) {
        return -1;
	}

    retval = vsnprintf(str, len + 1, format, ap);
    if (retval == -1) {
        free(str);
        return -1;
    }
    *strp = str;

    return retval;
}

int asprintf(char **strp, const char *format, ...) {
    int retval = 0;
    va_list ap;

    va_start(ap, format);
    retval = vasprintf(strp, format, ap);
    va_end(ap);

    return retval;
}
#endif

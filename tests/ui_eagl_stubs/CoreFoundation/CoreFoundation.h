#ifndef TEST_CORE_FOUNDATION_H
#define TEST_CORE_FOUNDATION_H
#include <stdbool.h>
typedef unsigned long CFTypeID;
typedef long CFIndex;
typedef const void *CFDictionaryRef;
enum { kCFNumberSInt64Type=4 };
const void *mock_cfstr(const char *);
#define CFSTR(value) mock_cfstr(value)
CFTypeID CFGetTypeID(const void *);
CFTypeID CFStringGetTypeID(void);
CFTypeID CFBooleanGetTypeID(void);
CFTypeID CFNumberGetTypeID(void);
bool CFBooleanGetValue(const void *);
bool CFNumberIsFloatType(const void *);
bool CFNumberGetValue(const void *,int,void *);
bool CFEqual(const void *,const void *);
CFIndex CFDictionaryGetCount(CFDictionaryRef);
void CFDictionaryGetKeysAndValues(CFDictionaryRef,const void **,const void **);
const void *CFDictionaryGetValue(CFDictionaryRef,const void *);
const void *CFRetain(const void *);
void CFRelease(const void *);
#endif

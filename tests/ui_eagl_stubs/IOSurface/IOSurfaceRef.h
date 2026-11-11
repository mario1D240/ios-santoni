#ifndef TEST_IOSURFACE_H
#define TEST_IOSURFACE_H
#include <stddef.h>
#include <stdint.h>
typedef struct test_surface *IOSurfaceRef;
enum {kIOSurfaceLockReadOnly=1};
int IOSurfaceLock(IOSurfaceRef,uint32_t,uint32_t *);
int IOSurfaceUnlock(IOSurfaceRef,uint32_t,uint32_t *);
size_t IOSurfaceGetWidth(IOSurfaceRef);
size_t IOSurfaceGetHeight(IOSurfaceRef);
size_t IOSurfaceGetBytesPerRow(IOSurfaceRef);
size_t IOSurfaceGetBytesPerElement(IOSurfaceRef);
size_t IOSurfaceGetPlaneCount(IOSurfaceRef);
size_t IOSurfaceGetAllocSize(IOSurfaceRef);
uint32_t IOSurfaceGetPixelFormat(IOSurfaceRef);
void *IOSurfaceGetBaseAddress(IOSurfaceRef);
#endif

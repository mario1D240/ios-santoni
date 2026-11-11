/* Only the libdrm dialect consumed by pinned Mesa's msm backend is exported.
 * No Linux fd, PRIME, sync-file, KMS or shared-owner interface exists on iOS. */
#ifndef SANTONI_XF86DRM_H
#define SANTONI_XF86DRM_H
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include "drm-uapi/drm.h"
#define DRM_NODE_PRIMARY 0
#define DRM_NODE_CONTROL 1
#define DRM_NODE_RENDER 2
#define DRM_NODE_MAX 3
#ifdef __cplusplus
extern "C" {
#endif
typedef struct _drmVersion {
    int version_major,version_minor,version_patchlevel;
    int name_len;char *name;
    int date_len;char *date;
    int desc_len;char *desc;
} drmVersion,*drmVersionPtr;
int drmOpenWithType(const char *,const char *,int);
drmVersionPtr drmGetVersion(int);
void drmFreeVersion(drmVersionPtr);
int drmGetCap(int,uint64_t,uint64_t *);
int drmIoctl(int,unsigned long,void *);
int drmCommandWrite(int,unsigned long,void *,unsigned long);
int drmCommandWriteRead(int,unsigned long,void *,unsigned long);
int drmPrimeHandleToFD(int,uint32_t,uint32_t,int *);
int drmPrimeFDToHandle(int,int,uint32_t *);
int drmSyncobjCreate(int,uint32_t,uint32_t *);
int drmSyncobjDestroy(int,uint32_t);
int drmSyncobjHandleToFD(int,uint32_t,int *);
int drmSyncobjFDToHandle(int,int,uint32_t *);
int drmSyncobjImportSyncFile(int,uint32_t,int);
int drmSyncobjExportSyncFile(int,uint32_t,int *);
int drmSyncobjReset(int,const uint32_t *,uint32_t);
int drmSyncobjWait(int,uint32_t *,unsigned,int64_t,unsigned,uint32_t *);
int drmSyncobjTimelineWait(int,uint32_t *,uint64_t *,unsigned,int64_t,unsigned,uint32_t *);
#ifdef __cplusplus
}
#endif
#endif

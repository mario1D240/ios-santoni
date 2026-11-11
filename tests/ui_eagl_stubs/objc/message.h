#ifndef TEST_OBJC_MESSAGE_H
#define TEST_OBJC_MESSAGE_H
#include "runtime.h"
struct objc_super {id receiver;Class super_class;};
#ifndef SGFX_MESSAGE_IMPLEMENTATION
void objc_msgSend(void); /* Same untyped declaration as the modern SDK. */
#endif
void objc_msgSendSuper(struct objc_super *,SEL);
#endif

#ifndef TEST_OBJC_RUNTIME_H
#define TEST_OBJC_RUNTIME_H
typedef struct test_object *id;
typedef struct test_class *Class;
typedef const char *SEL;
typedef void (*IMP)(void);
typedef struct test_method *Method;
#define nil ((id)0)
Class objc_getClass(const char *);
Class object_getClass(id);
Class class_getSuperclass(Class);
SEL sel_registerName(const char *);
Method class_getClassMethod(Class,SEL);
Method class_getInstanceMethod(Class,SEL);
const char *method_getTypeEncoding(Method);
IMP method_getImplementation(Method);
IMP method_setImplementation(Method,IMP);
id class_createInstance(Class,unsigned long);
#endif

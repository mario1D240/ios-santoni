/* Actual Mesa clear/triangle/texture command generation on a HOST model.
 * No pixel readback, hardware pass, kernel certificate or device access. */
#include "gles.h"
#include <GLES2/gl2.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
unsigned sgfx_capture_count(void);
static unsigned dimension(const char *name)
{
    const char *text=getenv(name);if(!text)return 64;
    if(*text<'0' || *text>'9')return 0;
    char *end=NULL;errno=0;unsigned long value=strtoul(text,&end,10);
    return !errno && end && !*end && value && value<=4096?(unsigned)value:0;
}
static GLuint compile(GLenum type,const char *source)
{
    GLuint shader=glCreateShader(type);glShaderSource(shader,1,&source,NULL);glCompileShader(shader);
    GLint good=0;glGetShaderiv(shader,GL_COMPILE_STATUS,&good);
    if(!good) {char log[1024]={0};glGetShaderInfoLog(shader,sizeof(log),NULL,log);fprintf(stderr,"shader: %s\n",log);return 0;}
    return shader;
}
static bool ui_quad(GLuint source,GLuint vertices)
{
    /* UI-like interpolation/premultiplied blending command evidence only.
     * This is not an Apple shader capture or a physical UI/pixel result. */
    if(!source || !vertices)return false;
    GLuint vs=compile(GL_VERTEX_SHADER,
        "attribute vec2 pos;varying highp vec2 uv;void main(){gl_Position=vec4(pos,0.,1.);uv=pos*.5+.5;}");
    GLuint fs=compile(GL_FRAGMENT_SHADER,
        "precision highp float;varying highp vec2 uv;uniform sampler2D tex;void main(){gl_FragColor=texture2D(tex,uv)*vec4(.5);}");
    if(!vs || !fs)return false;
    GLuint program=glCreateProgram();glAttachShader(program,vs);glAttachShader(program,fs);glBindAttribLocation(program,0,"pos");
    glLinkProgram(program);GLint linked=0;glGetProgramiv(program,GL_LINK_STATUS,&linked);if(!linked)return false;
    glUseProgram(program);glActiveTexture(GL_TEXTURE0);glBindTexture(GL_TEXTURE_2D,source);
    glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,GL_LINEAR);glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,GL_LINEAR);
    glUniform1i(glGetUniformLocation(program,"tex"),0);
    const GLfloat data[]={-1,-1,1,-1,-1,1,1,1};
    glBindBuffer(GL_ARRAY_BUFFER,vertices);glBufferData(GL_ARRAY_BUFFER,sizeof(data),data,GL_STATIC_DRAW);
    glEnableVertexAttribArray(0);glVertexAttribPointer(0,2,GL_FLOAT,GL_FALSE,0,NULL);
    glEnable(GL_BLEND);glBlendFunc(GL_ONE,GL_ONE_MINUS_SRC_ALPHA);glDrawArrays(GL_TRIANGLE_STRIP,0,4);glFinish();glDisable(GL_BLEND);
    return glGetError()==GL_NO_ERROR;
}
int main(void)
{
    unsigned width=dimension("SANTONI_CAPTURE_WIDTH"),height=dimension("SANTONI_CAPTURE_HEIGHT");
    const char *profile=getenv("SANTONI_CAPTURE_UI");
    if(profile && strcmp(profile,"0") && strcmp(profile,"1"))return 1;
    bool ui=profile && !strcmp(profile,"1");
    if(!width || !height)return 1;
    fprintf(stderr,"CAPTURE stage=create-context; width=%u height=%u hardware_verified=0\n",width,height);
    struct sgfx_gles_context *context=sgfx_gles_create();
    if(!context || !sgfx_gles_current(context))return 1;
    fprintf(stderr,"CAPTURE stage=create-target\n");
    GLuint texture=0,framebuffer=0,vertices=0;glGenTextures(1,&texture);glBindTexture(GL_TEXTURE_2D,texture);
    glTexImage2D(GL_TEXTURE_2D,0,GL_RGBA,(GLsizei)width,(GLsizei)height,0,GL_RGBA,GL_UNSIGNED_BYTE,NULL);
    glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,GL_NEAREST);glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,GL_NEAREST);
    glGenFramebuffers(1,&framebuffer);glBindFramebuffer(GL_FRAMEBUFFER,framebuffer);
    glFramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,texture,0);
    if(glCheckFramebufferStatus(GL_FRAMEBUFFER)!=GL_FRAMEBUFFER_COMPLETE)return 1;
    glViewport(0,0,(GLsizei)width,(GLsizei)height);glClearColor(0,0,1,1);glClear(GL_COLOR_BUFFER_BIT);glFinish();
    unsigned clear=sgfx_capture_count();fprintf(stderr,"CAPTURE stage=clear generated=%u\n",clear);
    GLuint vs=compile(GL_VERTEX_SHADER,"attribute vec2 pos;void main(){gl_Position=vec4(pos,0.,1.);}");
    GLuint fs=compile(GL_FRAGMENT_SHADER,"precision highp float;void main(){gl_FragColor=vec4(1.,0.,0.,1.);}");
    if(!vs || !fs)return 1;
    GLuint program=glCreateProgram();glAttachShader(program,vs);glAttachShader(program,fs);glBindAttribLocation(program,0,"pos");
    glLinkProgram(program);GLint linked=0;glGetProgramiv(program,GL_LINK_STATUS,&linked);if(!linked)return 1;
    glUseProgram(program);const GLfloat data[]={-1,-1,1,-1,-1,1};
    glGenBuffers(1,&vertices);glBindBuffer(GL_ARRAY_BUFFER,vertices);glBufferData(GL_ARRAY_BUFFER,sizeof(data),data,GL_STATIC_DRAW);
    glEnableVertexAttribArray(0);glVertexAttribPointer(0,2,GL_FLOAT,GL_FALSE,0,NULL);
    glDrawArrays(GL_TRIANGLES,0,3);glFinish();unsigned triangle=sgfx_capture_count();
    fprintf(stderr,"CAPTURE stage=triangle generated=%u\n",triangle);
    GLuint source=0;uint8_t pixels[16*16*4];for(unsigned i=0;i<sizeof(pixels);i++)pixels[i]=(uint8_t)i;
    glGenTextures(1,&source);glBindTexture(GL_TEXTURE_2D,source);glTexImage2D(GL_TEXTURE_2D,0,GL_RGBA,16,16,0,GL_RGBA,GL_UNSIGNED_BYTE,pixels);
    glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,GL_NEAREST);glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,GL_NEAREST);
    char fragment[256];int length=snprintf(fragment,sizeof(fragment),
        "precision highp float;uniform sampler2D tex;void main(){gl_FragColor=texture2D(tex,gl_FragCoord.xy/vec2(%u.,%u.));}",width,height);
    if(length<0 || (size_t)length>=sizeof(fragment))return 1;
    GLuint textured=compile(GL_FRAGMENT_SHADER,fragment);
    if(!textured)return 1;
    GLuint second=glCreateProgram();glAttachShader(second,vs);glAttachShader(second,textured);glBindAttribLocation(second,0,"pos");
    glLinkProgram(second);glGetProgramiv(second,GL_LINK_STATUS,&linked);if(!linked)return 1;
    glUseProgram(second);glUniform1i(glGetUniformLocation(second,"tex"),0);glDrawArrays(GL_TRIANGLES,0,3);glFinish();
    unsigned sampled=sgfx_capture_count();bool good=glGetError()==GL_NO_ERROR && clear>0 && triangle>clear && sampled>triangle;
    unsigned quad=0;
    if(good && ui) {good=ui_quad(source,vertices);quad=sgfx_capture_count();good=good && quad>sampled;}
    printf("CAPTURE generated=%u clear=%u triangle=%u sampled=%u ui_like_quad=%u; GPU/admission/completion MODELED; hardware_verified=0\n",
        good?1u:0u,clear,triangle,sampled,quad);
    sgfx_gles_destroy(context);return good?0:1;
}

/* Rectangle normalization pattern: ios-sailfish/tools/sweetgl/eagl.c.
 * Unlike a substring rewrite, comments and source lengths do not supply
 * sampler metadata. Shader/raster admission remains the kernel's obligation. */
#include "ui_shader.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
struct token {size_t start,bytes;};
static bool letter(char ch)
{return (ch>='a' && ch<='z') || (ch>='A' && ch<='Z') || ch=='_';}
static bool space(char ch) {return ch==' ' || ch=='\t' || ch=='\r' || ch=='\n';}
static bool next(const char *text,size_t bytes,size_t *position,struct token *out)
{
    size_t pos=*position;
    for(;;) {
        while(pos<bytes && space(text[pos]))pos++;
        if(pos+1<bytes && text[pos]=='/' && text[pos+1]=='/') {
            while(pos<bytes && text[pos]!='\n')pos++;continue;
        }
        if(pos+1<bytes && text[pos]=='/' && text[pos+1]=='*') {
            pos+=2;while(pos+1<bytes && !(text[pos]=='*' && text[pos+1]=='/'))pos++;
            if(pos>=bytes-1)return false;pos+=2;continue;
        }
        break;
    }
    if(pos==bytes) {*position=pos;out->bytes=0;return true;}
    size_t start=pos++;
    if(letter(text[start]))while(pos<bytes && (letter(text[pos]) || (text[pos]>='0' && text[pos]<='9')))pos++;
    *out=(struct token){start,pos-start};*position=pos;return true;
}
static bool equal(const char *text,struct token token,const char *word)
{return token.bytes==strlen(word) && !memcmp(text+token.start,word,token.bytes);}
char *sgfx_ui_shader_source(int32_t count,const char *const *parts,const int32_t *length,char sampler[SGFX_UI_SHADER_NAME])
{
    if(!sampler)return NULL;memset(sampler,0,SGFX_UI_SHADER_NAME);
    if(count<0 || count>64 || (count && !parts))return NULL;
    size_t sizes[64],bytes=0;
    for(int32_t i=0;i<count;i++) {
        if(!parts[i])return NULL;
        size_t n=0;
        if(length && length[i]>=0)n=(size_t)length[i];
        else {while(n<=SGFX_UI_SHADER_BYTES && parts[i][n])n++;}
        if(n>SGFX_UI_SHADER_BYTES-bytes || memchr(parts[i],0,n))return NULL;
        sizes[i]=n;bytes+=n;
    }
    char *source=malloc(bytes+1);if(!source)return NULL;
    size_t pos=0;for(int32_t i=0;i<count;i++) {memcpy(source+pos,parts[i],sizes[i]);pos+=sizes[i];}source[bytes]=0;
    size_t at=0,scan=0;struct token token={0};bool modern=false;
    /* Insert after leading preprocessor lines, leaving #version first and
     * extension directives ahead of the new uniform declaration. */
    while(next(source,bytes,&scan,&token) && token.bytes) {
        if(!equal(source,token,"#"))break;
        struct token directive={0};if(!next(source,bytes,&scan,&directive))goto bad;
        if(equal(source,directive,"version")) {
            size_t number=scan;while(number<bytes && space(source[number]))number++;
            modern=number+3<=bytes && !memcmp(source+number,"300",3);
        }
        while(scan<bytes && source[scan]!='\n')scan++;
        if(scan<bytes)scan++;at=scan;
    }
    scan=0;bool use_rect=false,projected=false;
    while(next(source,bytes,&scan,&token) && token.bytes) {
        if(equal(source,token,"gl_LastFragData"))goto bad;
        if(equal(source,token,"texture2DRectProj"))projected=true;
        if(equal(source,token,"sampler2DRect")) {
            struct token name={0},terminator={0};
            if(!next(source,bytes,&scan,&name) || !name.bytes || !letter(source[name.start]) ||
                name.bytes>=SGFX_UI_SHADER_NAME || !next(source,bytes,&scan,&terminator) || !equal(source,terminator,";"))goto bad;
            if(sampler[0] && (strlen(sampler)!=name.bytes || memcmp(sampler,source+name.start,name.bytes)))goto bad;
            memcpy(sampler,source+name.start,name.bytes);sampler[name.bytes]=0;use_rect=true;
        }
    }
    if(scan<bytes)goto bad; /* Unterminated comment, never partial metadata. */
    if(!use_rect)return source;
    if(strstr(source,"sgfx_rect_scale") || strstr(source,"sgfx_rect_project"))goto bad;
    const char *prefix=modern?
        "#define sampler2DRect sampler2D\n#define texture2DRect(s,c) texture(s,(c)*sgfx_rect_scale)\nuniform highp vec2 sgfx_rect_scale;\n":
        "#define sampler2DRect sampler2D\n#define texture2DRect(s,c) texture2D(s,(c)*sgfx_rect_scale)\nuniform highp vec2 sgfx_rect_scale;\n";
    /* CA's texture%sProj template also accepts rectangle coordinates. Scale
     * only xy; texture*Proj divides by z for vec3 and w for vec4. Overloads
     * preserve that denominator and evaluate the coordinate expression once. */
    const char *projection=projected?(modern?
        "#define texture2DRectProj(s,c) textureProj(s,sgfx_rect_project(c))\n":
        "#define texture2DRectProj(s,c) texture2DProj(s,sgfx_rect_project(c))\n"):"";
    const char *helpers=projected?
        "highp vec3 sgfx_rect_project(highp vec3 c) { return vec3(c.xy*sgfx_rect_scale,c.z); }\n"
        "highp vec4 sgfx_rect_project(highp vec4 c) { return vec4(c.xy*sgfx_rect_scale,c.zw); }\n":"";
    size_t prefix_bytes=strlen(prefix),projection_bytes=strlen(projection),helper_bytes=strlen(helpers);
    size_t extra=prefix_bytes+projection_bytes+helper_bytes;
    char *out=malloc(bytes+extra+1);if(!out)goto bad;
    memcpy(out,source,at);memcpy(out+at,prefix,prefix_bytes);
    memcpy(out+at+prefix_bytes,projection,projection_bytes);
    memcpy(out+at+prefix_bytes+projection_bytes,helpers,helper_bytes);
    memcpy(out+at+extra,source+at,bytes-at+1);free(source);return out;
bad:
    free(source);sampler[0]=0;return NULL;
}

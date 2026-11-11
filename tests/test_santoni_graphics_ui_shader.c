#include "ui_shader.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char **argv)
{
    if(argc==3 && !strcmp(argv[1],"source")) {
        char sampler[SGFX_UI_SHADER_NAME];const char *part=argv[2];
        char *source=sgfx_ui_shader_source(1,&part,NULL,sampler);
        if(!source)return 1;fputs(source,stdout);free(source);return 0;
    }
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],NULL,10);assert(test<24);
    char name[SGFX_UI_SHADER_NAME];const char *parts[2]={"uniform lowp sampler2DRect tex;\nvoid main(){texture2DRect(tex,vec2(2.));}",NULL};
    int32_t lengths[2]={-1,-1};int32_t count=1;
    switch(test) {
    case 1:parts[0]="// sampler2DRect fake;\nvoid main(){}";break;
    case 2:parts[0]="/* sampler2DRect fake; */\n#version 300 es\n#extension GL_EXT_example : enable\nuniform sampler2DRect tex;";break;
    case 3:parts[0]="uniform sampler2DRect tex[2];";break;
    case 4:parts[0]="uniform sampler2DRect one; uniform sampler2DRect two;";break;
    case 5:parts[0]="uniform sampler2DRect tex; void main(){gl_LastFragData[0];}";break;
    case 6:parts[0]="uniform sampler2DRect tex; uniform vec2 sgfx_rect_scale;";break;
    case 7:parts[0]="/* unterminated sampler2DRect tex;";break;
    case 8:parts[0]="uniform sampler";parts[1]="2DRect tex;";count=2;lengths[0]=15;break;
    case 9:parts[0]="a\0b";lengths[0]=3;break;
    case 10:parts[0]=NULL;break;
    case 11:count=65;break;
    case 12:parts[0]="uniform sampler2DRect tex; void main(){texture2DRectProj(tex,vec3(2.));}";break;
    case 13:parts[0]="uniform sampler2DRect tex; void main(){texture2DRectProj(tex,vec4(2.));}";break;
    case 14:parts[0]="#version 300 es\nuniform sampler2DRect tex; void main(){texture2DRectProj(tex,vec3(2.));}";break;
    case 15:parts[0]="#version 300 es\nuniform sampler2DRect tex; void main(){texture2DRectProj(tex,vec4(2.));}";break;
    case 16:parts[0]="uniform sampler2DRect tex; // texture2DRectProj(tex,c)\nvoid main(){}";break;
    case 17:parts[0]="uniform sampler2D tex; void main(){texture2DProj(tex,vec4(2.));}";break;
    case 18:parts[0]="uniform sampler2DRect tex; uniform vec4 sgfx_rect_project;";break;
    case 19:parts[0]="uniform sampler2DRect tex[2]; void main(){texture2DRectProj(tex[0],vec3(2.));}";break;
    case 20:parts[0]="uniform sampler2DRect tex; void main(){texture2DRect";parts[1]="Proj(tex,vec4(2.));}";count=2;break;
    case 21:parts[0]="uniform sampler2DRect tex; texture2DRectProj(tex,c); /* unterminated";break;
    case 22:parts[0]="uniform sampler2DRect tex; texture2DRectProj(tex,c); gl_LastFragData[0];";break;
    case 23:parts[0]="uniform sampler2DRect one; uniform sampler2DRect two; texture2DRectProj(one,c);";break;
    default:break;
    }
    char *source=sgfx_ui_shader_source(count,parts,lengths,name);
    bool projected=(test>=12 && test<=15) || test==20;
    bool good=test==0 || test==1 || test==2 || test==8 || projected || test==16 || test==17;
    assert((source!=NULL)==good);
    if(good) {
        if(test==1 || test==17)assert(!name[0] && !strcmp(source,parts[0]));
        else {
            assert(!strcmp(name,"tex") && strstr(source,"uniform highp vec2 sgfx_rect_scale;"));
            if(test==2)assert(strstr(source,"#version 300 es")<strstr(source,"#extension GL_EXT_example") &&
                strstr(source,"#extension GL_EXT_example")<strstr(source,"#define sampler2DRect") &&
                strstr(source,"texture(s,"));
            else if(test==14 || test==15)assert(strstr(source,"texture(s,") &&
                strstr(source,"#version 300 es")<strstr(source,"#define sampler2DRect"));
            else assert(strstr(source,"texture2D(s,"));
            if(projected) {
                assert(strstr(source,(test==14 || test==15)?
                    "textureProj(s,sgfx_rect_project(c))":"texture2DProj(s,sgfx_rect_project(c))"));
                assert(strstr(source,"vec3(c.xy*sgfx_rect_scale,c.z)") &&
                    strstr(source,"vec4(c.xy*sgfx_rect_scale,c.zw)"));
            } else assert(!strstr(source,"sgfx_rect_project"));
        }
    } else assert(!name[0]);
    free(source);printf("PASS shader source case=%u; no compiler/hardware claim\n",test);return 0;
}

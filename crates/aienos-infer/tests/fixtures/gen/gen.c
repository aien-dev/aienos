/* Regenerates ../q4k.* and ../q6k.* : blocks cut from the real GGUF plus the
 * output of ggml dequantize_row_q4_K/q6_K. Run via ../../../tools or `make -C gen`.
 * Usage: gen <outdir> */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
extern void dequantize_row_q4_K(const void*, float*, int64_t);
extern void dequantize_row_q6_K(const void*, float*, int64_t);
static void go(const char*f,int q6,long offs[2],const char*pfx){
  int bs=q6?210:144; int nb=4; char n[256];
  snprintf(n,256,"%s.bin",pfx); FILE*o=fopen(n,"wb");
  snprintf(n,256,"%s.f32",pfx); FILE*r=fopen(n,"wb");
  FILE*in=fopen(f,"rb");
  for(int t=0;t<2;t++){ fseek(in,offs[t],SEEK_SET); unsigned char*buf=malloc(bs*nb); fread(buf,bs,nb,in); fwrite(buf,bs,nb,o);
    float*y=malloc(256*nb*4); if(q6)dequantize_row_q6_K(buf,y,256*nb); else dequantize_row_q4_K(buf,y,256*nb); fwrite(y,4,256*nb,r);}
  fclose(o);fclose(r);fclose(in);}
int main(int argc,char**argv){const char*d=argc>1?argv[1]:".";const char*f="/home/drakestapleton/models/aien-mail/Llama-3.2-1B-Instruct-Q4_K_M.gguf";
 long a[2]={223309856,798257184}, b[2]={228626464,775049248};
 char p4[300],p6[300];snprintf(p4,300,"%s/q4k",d);snprintf(p6,300,"%s/q6k",d);go(f,0,a,p4);go(f,1,b,p6);return 0;}

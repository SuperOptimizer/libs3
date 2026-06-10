// bench_ranged — characterize the mc_s3-style workload: many ranged GETs.
// P: s3_prewarm (pays the TLS handshakes up front)
// A: sequential s3_get_range (warm thread handle)
// B: s3_get_batch with coalescing disabled, 3 rounds (raw batch path;
//    round 1 is warm because of P)
// C: big single GET (reference bytes + buffer-growth cost)
// D: s3_get_parallel scatter-direct, byte-verified against C
// E: s3_get_batch with default coalescing (adjacent ranges -> one
//    transfer), every member byte-verified against C
#include "../libs3.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
static double now(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return ts.tv_sec+ts.tv_nsec*1e-9; }
#define URL "s3://vesuvius-challenge-open-data/PHercParis4/volumes/20260323153942-2.400um-0.2m-137keV-masked.zarr/0/26/33/33"
int main(void){
    s3_config cfg={0};
    cfg.coalesce_gap=-1;                 // raw batch path for A-D
    s3_client *cl=s3_client_new(&cfg);
    s3_config cfg2={0};                  // default coalescing for E
    s3_client *cl2=s3_client_new(&cfg2);
    s3_response r={0};
    double t0=now();
    if(s3_head(cl,URL,&r)!=S3_OK||!s3_response_ok(&r)){ fprintf(stderr,"head failed: %s\n",s3_client_last_error(cl)); return 1; }
    printf("object: %llu bytes  (head: %.0f ms)\n",(unsigned long long)r.content_length,(now()-t0)*1e3);
    uint64_t objlen=r.content_length;
    s3_response_free(&r);

    enum { N=32 };
    const uint64_t RSZ=64*1024;

    // P: prewarm the batch pool (this thread)
    t0=now();
    if(s3_prewarm(cl,URL,16)!=S3_OK){ fprintf(stderr,"prewarm failed: %s\n",s3_client_last_error(cl)); return 1; }
    printf("P prewarm    : 16 conns in %6.0f ms\n",(now()-t0)*1e3);

    // A: sequential ranged GETs
    t0=now();
    for(int i=0;i<N;++i){
        s3_response rr={0};
        if(s3_get_range(cl,URL,(uint64_t)i*RSZ%(objlen-RSZ),RSZ,&rr)!=S3_OK){ fprintf(stderr,"range %d failed\n",i); return 1; }
        s3_response_free(&rr);
    }
    double ta=now()-t0;
    printf("A sequential : %d x 64KB in %6.0f ms (%5.1f ms/req, %5.2f MB/s)\n",N,ta*1e3,ta*1e3/N,N*RSZ/1e6/ta);

    // B: batched, coalescing disabled — three rounds (round 1 warm via P)
    s3_range_req reqs[N]; s3_response outs[N];
    for(int round=0;round<3;++round){
        for(int i=0;i<N;++i){
            reqs[i]=(s3_range_req){.url=URL,.offset=(uint64_t)i*RSZ%(objlen-RSZ),.length=RSZ};
            memset(&outs[i],0,sizeof outs[i]);
        }
        t0=now();
        if(s3_get_batch(cl,reqs,N,0,outs)!=S3_OK){ fprintf(stderr,"get_batch failed: %s\n",s3_client_last_error(cl)); return 1; }
        double tb=now()-t0;
        printf("B get_batch #%d: %d x 64KB in %6.0f ms (%5.1f ms/req-equiv, %5.2f MB/s)\n",round+1,N,tb*1e3,tb*1e3/N,N*RSZ/1e6/tb);
        for(int i=0;i<N;++i) s3_response_free(&outs[i]);
    }

    // C: one big GET (16MB range)
    t0=now();
    s3_response big={0};
    uint64_t BIG=16*1024*1024;
    if(s3_get_range(cl,URL,0,BIG<objlen?BIG:objlen,&big)!=S3_OK){ fprintf(stderr,"big failed\n"); return 1; }
    double tc=now()-t0;
    printf("C big GET    : %.0f MB in %6.0f ms (%6.1f MB/s)\n",big.body_len/1e6,tc*1e3,big.body_len/1e6/tc);
    // D: parallel whole-object download (scatter-direct), twice — verify
    // byte-identical to the plain GET (covers the fixed-sink scatter path)
    for(int round=0;round<2;++round){
        s3_response pr={0};
        t0=now();
        if(s3_get_parallel(cl,URL,0,0,512*1024,8,&pr)!=S3_OK){ fprintf(stderr,"parallel failed: %s\n",s3_client_last_error(cl)); return 1; }
        double td=now()-t0;
        int same = pr.body_len>=big.body_len ? !memcmp(pr.body,big.body,big.body_len) : 0;
        printf("D parallel #%d: %.0f MB in %6.0f ms (%6.1f MB/s) %s\n",round+1,pr.body_len/1e6,td*1e3,pr.body_len/1e6/td, same?"BYTES-OK":"BYTES-MISMATCH");
        if(!same){ s3_response_free(&pr); return 1; }
        s3_response_free(&pr);
    }

    // E: coalescing on — adjacent (gap 0) and gapped (128KB < 256KB
    // threshold), submitted out-of-order; every member byte-verified vs C.
    struct { const char *name; uint64_t stride; int cnt; } evar[2]={{"adjacent",RSZ,N},{"gap128K ",RSZ+128*1024,10}};
    for(int v=0;v<2;++v){
        int M=evar[v].cnt;
        for(int round=0;round<2;++round){
            for(int i=0;i<M;++i){
                reqs[i]=(s3_range_req){.url=URL,.offset=(uint64_t)(M-1-i)*evar[v].stride,.length=RSZ};
                memset(&outs[i],0,sizeof outs[i]);
            }
            if(reqs[0].offset+RSZ>big.body_len){ fprintf(stderr,"E ranges exceed reference\n"); return 1; }
            t0=now();
            if(s3_get_batch(cl2,reqs,M,0,outs)!=S3_OK){ fprintf(stderr,"E get_batch failed: %s\n",s3_client_last_error(cl2)); return 1; }
            double te=now()-t0;
            int ok=1;
            for(int i=0;i<M;++i){
                if(outs[i].status!=206||outs[i].body_len!=RSZ||
                   memcmp(outs[i].body,big.body+reqs[i].offset,RSZ)){ ok=0; break; }
            }
            printf("E coalesced %s #%d: %d x 64KB in %6.0f ms (%5.1f ms/req-equiv) %s\n",
                   evar[v].name,round+1,M,te*1e3,te*1e3/M,ok?"BYTES-OK":"BYTES-MISMATCH");
            for(int i=0;i<M;++i) s3_response_free(&outs[i]);
            if(!ok) return 1;
        }
    }
    s3_response_free(&big);
    s3_client_free(cl);
    s3_client_free(cl2);
    return 0;
}

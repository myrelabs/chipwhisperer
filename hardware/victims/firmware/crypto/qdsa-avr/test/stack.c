#include <stdlib.h>
#include "print.h"
#include "fail.h"
#include "avr.h"
#include "../sign.h"
#include "../scalar.h"
#include "../fe25519.h"

#define nlen 32
#define qlen 32

unsigned char i;
unsigned char n[nlen];
unsigned char q[qlen];

unsigned int ctr=0,newctr;
unsigned char canary;
volatile unsigned char *p;
extern unsigned char _end; 
extern unsigned char __stack; 

unsigned char sk[64];
unsigned long long mlen = 64;
unsigned char pk[32];
unsigned char sm[128];
unsigned long long smlen;
ecp r;
group_scalar s;

static unsigned int stack_count(unsigned char canary)
{
  const unsigned char *p = &_end;
  unsigned int c = 0;
  while(*p == canary && p <= &__stack)
  {
    p++;
    c++;
  }
  return c;
} 

#define WRITE_CANARY(X) {p=X;while(p>= &_end) *(p--) = canary;}
 
int main(void)
{
  volatile unsigned char a; /* Mark the beginning of the stack */

  for(i=0;i<5;i++)
  {
    canary = random();
    WRITE_CANARY(&a);
    hash(sm, sk, 64);
    newctr =(unsigned int)&a - (unsigned int)&_end - stack_count(canary);
    ctr = (newctr>ctr)?newctr:ctr;
  }
  print_stack("hash",-1,ctr);

  for(i=0;i<5;i++)
  {
    canary = random();
    WRITE_CANARY(&a);
    ladder_base(&r, &s);
    newctr =(unsigned int)&a - (unsigned int)&_end - stack_count(canary);
    ctr = (newctr>ctr)?newctr:ctr;
  }
  print_stack("ladder_base",-1,ctr);

  for(i=0;i<5;i++)
  {
    canary = random();
    WRITE_CANARY(&a);
    keypair(pk, sk);
    newctr =(unsigned int)&a - (unsigned int)&_end - stack_count(canary);
    ctr = (newctr>ctr)?newctr:ctr;
  }
  print_stack("keypair",-1,ctr);

  for(i=0;i<5;i++)
  {
    canary = random();
    WRITE_CANARY(&a);
    sign(sm, &smlen, sm+64, mlen, pk, sk);
    newctr =(unsigned int)&a - (unsigned int)&_end - stack_count(canary);
    ctr = (newctr>ctr)?newctr:ctr;
  }
  print_stack("sign",-1,ctr);

  for(i=0;i<5;i++)
  {
    canary = random();
    WRITE_CANARY(&a);
    verify(sm+64, mlen, sm, smlen, pk);
    newctr =(unsigned int)&a - (unsigned int)&_end - stack_count(canary);
    ctr = (newctr>ctr)?newctr:ctr;
  }
  print_stack("verify",-1,ctr);

  avr_end();
  return 0;
}

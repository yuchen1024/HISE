/****************************************************************************
this C file implements global escrow ElGamal PKE (from Joux's 3-party NIKE)
inherently relies on symmetric pairing
*****************************************************************************
* @author     Yu Chen
* @paper      HISE
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#include "relic/relic.h"
#include <stdio.h>
#include <time.h>

int LINE_LEN = 120;     // the length of split line

/* print split line */
void Print_SplitLine(char ch)
{
    for (int i = 0; i < LINE_LEN; i++) printf("%c", ch);  
    printf("\n");
}

struct Global_Escrow_PKE_PP
{
    ep_t g; 
    bn_t order; 
    ep_t epk; 
};

struct Global_Escrow_PKE_CT
{
    ep_t receiver_pk;  
    ep_t X; 
};

void Global_Escrow_PKE_Setup(struct Global_Escrow_PKE_PP *pp, bn_t *esk)
{
    ep_rand(pp->g); 
    ep_curve_get_ord(pp->order);

    bn_rand_mod(*esk, pp->order); // sample esk
    ep_mul(pp->epk, pp->g, *esk); // epk = g^esk
}

// generate pk and sk
void Global_Escrow_PKE_KeyGen(struct Global_Escrow_PKE_PP *pp, ep_t *pk, bn_t *sk)
{
    bn_rand_mod(*sk, pp->order);
    ep_mul(*pk, pp->g, *sk);          // pk = g^sk
}

// generate pk and sk
void Global_Escrow_PKE_Encaps(struct Global_Escrow_PKE_PP *pp, ep_t *pk, struct Global_Escrow_PKE_CT *ct, fp2_t *k)
{  
    bn_t r; bn_new(r); 
    bn_rand_mod(r, pp->order);
    ep_mul(ct->X, pp->g, r);          // X = g^r
    ep_copy(ct->receiver_pk, *pk); 
    pp_map_weilp_k2(*k, pp->epk, *pk); // K = e(pk, epk)
    fp2_exp(*k, *k, r);               // K = e(pk, epk)^r = ShareKey(X, pk, epk)
    bn_free(r); 
}

// generate pk and sk
void Global_Escrow_PKE_Decaps(struct Global_Escrow_PKE_PP *pp, 
                              struct Global_Escrow_PKE_CT *ct, bn_t *sk, fp2_t *k)
{  
    // normal decryption
    pp_map_weilp_k2(*k, ct->X, pp->epk); // k = e(X, epk)
    fp2_exp(*k, *k, *sk);                // k = e(X, epk)^sk
}

// generate pk and sk
void Global_Escrow_PKE_Escrow_Decaps(struct Global_Escrow_PKE_PP *pp, 
                                     struct Global_Escrow_PKE_CT *ct, bn_t *esk, fp2_t *k)
{  
    // normal decryption
    pp_map_weilp_k2(*k, ct->X, ct->receiver_pk); // k = e(X, epk)
    fp2_exp(*k, *k, *esk);                       // k = e(X, epk)^sk
}
   

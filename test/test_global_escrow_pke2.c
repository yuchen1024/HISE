/****************************************************************************
this C file implements global escrow ElGamal PKE (from Joux's 3-party NIKE)
inherently relies on symmetric pairing
*****************************************************************************
* @author     Yu Chen
* @paper      HISE
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#include "../global_escrow_pke/global_escrow_pke2.h"

int main() {
    Print_SplitLine('-'); 
    printf("***Boneh-Franklin Global Escrow PKE***\n");
    Print_SplitLine('-'); 
    printf("benchmark test begins >>> \n");
    Print_SplitLine('-'); 
    
    int TEST_NUM = 3000; 
    int i; 

    core_init();

    fp_param_set(SS_1536); //set base field
    
    ep_param_set(SS_P1536); //set 1536-bit supersingular curve

    struct Global_Escrow_PKE_PP pp;
    ep_new(pp.g); 
    bn_new(pp.order);
    ep_new(pp.epk); 

    bn_t esk; bn_new(esk);  
    
    // generate epk and esk
    clock_t start =clock();
    for (i = 0; i < TEST_NUM; ++i){
        Global_Escrow_PKE_Setup(&pp, &esk);
    }
    clock_t end = clock(); 
    double duration = (double)(end-start) / CLOCKS_PER_SEC;
    duration = duration * 1000 / TEST_NUM; 
    printf("average setup takes time=%f ms\n", duration);

    //bn_print(pp.order); // output p

    // generate pk and sk
    bn_t sk; bn_new(sk); 
    ep_t pk; ep_new(pk); 
    start = clock();
    for (i = 0; i < TEST_NUM; ++i){
        Global_Escrow_PKE_KeyGen(&pp, &pk, &sk); 
    }
    end = clock(); 
    duration = (double)(end-start) / CLOCKS_PER_SEC;
    duration = duration * 1000 / TEST_NUM; 
    printf("average keygen takes time=%f ms\n", duration);


    fp2_t k; fp2_new(k); 

    struct Global_Escrow_PKE_CT ct; 
    ep_new(ct.X); 
    ep_new(ct.receiver_pk); 

    // encryption
    start =clock();
    for (i = 0; i < TEST_NUM; ++i){
        Global_Escrow_PKE_Encaps(&pp, &pk, &ct, &k); 
    }
    end = clock(); 
    duration = (double)(end-start) / CLOCKS_PER_SEC;
    duration = duration * 1000 / TEST_NUM; 
    printf("average encryption takes time=%f ms\n", duration);


    // normal decryption
    fp2_t k_prime; fp2_new(k_prime);
    start =clock();
    for (i = 0; i < TEST_NUM; ++i){
        Global_Escrow_PKE_Decaps(&pp, &ct, &sk, &k_prime);
    }
    end = clock(); 
    duration = (double)(end-start) / CLOCKS_PER_SEC;
    duration = duration * 1000 / TEST_NUM; 
    printf("average normal decryption takes time=%f ms\n", duration);

    if(fp2_cmp(k, k_prime)== RLC_EQ) printf("normal decryption succeeds\n");
    else printf("normal decryption fails\n");

    // escrow decryption
    start =clock();
    for (i = 0; i < TEST_NUM; ++i){
        Global_Escrow_PKE_Escrow_Decaps(&pp, &ct, &esk, &k_prime);
    }
    end = clock(); 
    duration = (double)(end-start) / CLOCKS_PER_SEC;
    duration = duration * 1000 / TEST_NUM; 
    printf("average escrow decryption takes time=%f ms\n", duration);

    if(fp2_cmp(k, k_prime)== RLC_EQ) printf("escrow decryption succeeds\n");
    else printf("escrow decryption fails\n");


    ep_free(pp.g); ep_free(pp.epk); bn_free(pp.order); 
    bn_free(sk); ep_free(pk); 
    ep_free(ct.X); ep_free(ct.receiver_pk); 
    fp2_free(k); fp2_free(k_prime);  

    core_clean();
    
    Print_SplitLine('-'); 
    printf("benchmark test ends >>>\n");
    Print_SplitLine('-'); 
    return 0;
}

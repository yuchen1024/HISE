#define DEBUG
//#define LOG

#include "../common/print.hpp"
#include "../cpk/elgamal_pke.hpp"

int main()
{
    Print_SplitLine('-'); 
    std::cout << "*** ElGamal PKE (based on mcl) ***" << std::endl;
    std::cout << "benchmark test begins >>>" << std::endl;
    Print_SplitLine('-'); 

    size_t TEST_NUM = 3000; 

    // generate global pp
    ElGamal_PP pp; 
    ElGamal_Setup(pp); 

    // generate mpk and msk
    Fr sk; 
    Ec pk; 
    auto start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        ElGamal_KeyGen(pp, pk, sk); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "average keygen takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    // encrypt a random message
    ElGamal_CT ct; 
     
    Ec pt;
    Fr s; 
    s.setRand();
    Ec::mul(pt, pp.g, s);  
  
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        ElGamal_Encrypt(pp, pk, pt, ct);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;


    // decrypt ciphertext
    Ec pt_prime;
    start_time = std::chrono::steady_clock::now();
    for(auto i = 0; i < TEST_NUM; i++){
        ElGamal_Decrypt(sk, ct, pt_prime); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average decryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    #ifdef DEBUG 
    if (pt == pt_prime){
        std::cout << "enc/dec test succeeds" << std::endl;
    }
    else{
        std::cout << "enc/dec test fails" << std::endl;    
    }
    #endif

    Print_SplitLine('-'); 
    std::cout << "benchmark test ends >>>" << std::endl;
    Print_SplitLine('-'); 

    return 0; 
}


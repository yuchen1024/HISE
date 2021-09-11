//#define DEBUG

#include "../common/print.hpp"
#include "../global_escrow_pke/global_escrow_pke1.hpp"

int main()
{
    Print_SplitLine('-'); 
    std::cout << "global escrow PKE (ElGamal PKE + twisted Naor-Yung)" << std::endl;
    Print_SplitLine('-'); 
    std::cout << "benchmark test begins >>>" << std::endl;
    Print_SplitLine('-'); 

    size_t TEST_NUM = 1; 

    // generate global pp and esk
    Global_Escrow_PKE_PP pp;
    Fr esk; 

    auto start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        Global_Escrow_PKE_Setup(pp, esk);
    } 
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "average setup takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    // generate pk and sk
    Fr sk; 
    Ec pk; 
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        Global_Escrow_PKE_KeyGen(pp, pk, sk); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average keygen takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    // encrypt a random message
    Global_Escrow_PKE_CT ct; 
     
    Ec pt;
    Fr s; 
    s.setRand();
    Ec::mul(pt, pp.g, s); 
  
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        Global_Escrow_PKE_Encrypt(pp, pk, pt, ct);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    // decrypt ciphertext
    Ec pt_prime;
    start_time = std::chrono::steady_clock::now();
    for(auto i = 0; i < TEST_NUM; i++){
        Global_Escrow_PKE_Decrypt(pp, sk, ct, pt_prime); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average decryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    #ifdef DEBUG 
    if (pt == pt_prime){
        std::cout << "normal decryption succeeds" << std::endl;
    } 
    else{
        std::cout << "normal decryption fails" << std::endl;    
    }
    #endif

    // escrow decrypt ciphertext
    start_time = std::chrono::steady_clock::now();
    for(auto i = 0; i < TEST_NUM; i++){
        Global_Escrow_PKE_Escrow_Decrypt(pp, esk, ct, pt_prime); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average escrow decryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    #ifdef DEBUG 
    if (pt == pt_prime){
        std::cout << "escrow decryption succeeds" << std::endl;
    }
    else{
        std::cout << "escrow decryption fails" << std::endl;    
    }
    #endif

    Print_SplitLine('-'); 
    std::cout << "benchmark test ends >>>" << std::endl;
    Print_SplitLine('-'); 

    return 0; 
}


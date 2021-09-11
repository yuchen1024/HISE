#define DEBUG
//#define LOG

#include "../common/print.hpp"
#include "../global_escrow_hise/global_escrow_hise1.hpp"

int main()
{
    Print_SplitLine('-'); 
    std::cout << "*** global escrow HISE (derived from BF-IBE and twisted Naor-Yung paradigm) ***" << std::endl;
    Print_SplitLine('-'); 
    std::cout << "benchmark test begins >>>" << std::endl;
    Print_SplitLine('-'); 

    int TEST_NUM = 1; 

    long seed = time(NULL); // initialize the seed with current system time
    srand(time(NULL));

    // generate global pp and esk
    Global_Escrow_HISE_PP pp;
    G2 esk;  
    Global_Escrow_HISE_Setup(pp, esk); 

    // generate pk and sk
    Fr sk; 
    G1 pk; 
    auto start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        Global_Escrow_HISE_KeyGen(pp, pk, sk); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "average keygen takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    // derive dk from sk  
    G2 dk; 
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        Global_Escrow_HISE_Derive(pp, sk, dk); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average derivation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;


    // encrypt a random message
    Global_Escrow_HISE_CT ct; 
     
    GT pt(rand(), rand()); 
  
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        Global_Escrow_HISE_Encrypt(pp, pk, pt, ct);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;


    // decrypt ciphertext
    GT pt_prime;
    start_time = std::chrono::steady_clock::now();
    for(auto i = 0; i < TEST_NUM; i++){
        Global_Escrow_HISE_Decrypt(pp, dk, ct, pt_prime); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average decryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    #ifdef DEBUG 
    if (pt == pt_prime){
        std::cout << "normal enc/dec test succeeds" << std::endl;
    }
    else{
        std::cout << "normal enc/dec test fails" << std::endl;    
    }
    #endif

    // escrow decrypt ciphertext
    start_time = std::chrono::steady_clock::now();
    for(auto i = 0; i < TEST_NUM; i++){
        Global_Escrow_HISE_Escrow_Decrypt(pp, esk, ct, pt_prime); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average escrow decryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    #ifdef DEBUG 
    if (pt == pt_prime){
        std::cout << "escrow enc/dec test succeeds" << std::endl;
    }
    else{
        std::cout << "escrow enc/dec test fails" << std::endl;    
    }
    #endif


    // sign a message
    std::string msg(32, '1');
    G2 sig; 

    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        Global_Escrow_HISE_Sign(sk, msg, sig);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average signing takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        Global_Escrow_HISE_Verify(pp, pk, msg, sig); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    Print_SplitLine('-'); 
    std::cout << "benchmark test ends >>>" << std::endl;
    Print_SplitLine('-'); 

    return 0; 
}


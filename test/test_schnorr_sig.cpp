#define DEBUG
//#define LOG

#include "../common/print.hpp"
#include "../cpk/schnorr_sig.hpp"

int main()
{
    Print_SplitLine('-'); 
    std::cout << "*** Schnorr SIG (based on mcl) ***" << std::endl;
    Print_SplitLine('-'); 
    std::cout << "benchmark test begins >>>" << std::endl;
    Print_SplitLine('-'); 

    int TEST_NUM = 3000; 

    // generate global pp
    Schnorr_PP pp; 
    Schnorr_Setup(pp); 

    // generate mpk and msk
    Fr sk; 
    Ec pk; 
    auto start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        Schnorr_KeyGen(pp, pk, sk); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "average keygen takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    // sign a random message
    std::string msg = "who am I";  
  
    Schnorr_SIG sig; 
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        Schnorr_Sign(pp, sk, msg, sig);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average signing takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;


    // verify a signature
    start_time = std::chrono::steady_clock::now();
    for(auto i = 0; i < TEST_NUM; i++){
        Schnorr_Verify(pp, pk, msg, sig); 
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


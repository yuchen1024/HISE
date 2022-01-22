#define DEBUG
//#define LOG

#include "../common/print.hpp"
#include "../hies/hies.hpp"

int main()
{
    Print_SplitLine('-'); 
    std::cout << "*** HIES (derived from Boneh-Boyen 2-level HIBE) ***" << std::endl;
    Print_SplitLine('-'); 
    std::cout << "benchmark test begins >>>" << std::endl;
    Print_SplitLine('-'); 

    int TEST_NUM = 3000; 

    long seed = time(NULL); // initialize the seed with current system time
    srand(time(NULL));

    // generate global pp
    HIES::PP pp = HIES::Setup(); 

    // generate mpk and msk
    std::vector<HIES::SK> vec_dk(TEST_NUM); 
    std::vector<G2> vec_pk(TEST_NUM);

    auto start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        std::tie(vec_pk[i], vec_dk[i]) = HIES::KeyGen(pp); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "average keygen takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    // derive dk from sk  
    std::vector<HIES::SK> vec_sk(TEST_NUM); 
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        vec_sk[i] = HIES::Derive(pp, vec_dk[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average derivation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;


    // encaps
    std::vector<HIES::CT> vec_ct(TEST_NUM); 
    std::vector<GT> vec_key(TEST_NUM); 
  
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        std::tie(vec_ct[i], vec_key[i]) = HIES::Encaps(pp, vec_pk[i]);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;


    // decaps
    std::vector<GT> vec_key_prime(TEST_NUM);
    start_time = std::chrono::steady_clock::now();
    for(auto i = 0; i < TEST_NUM; i++){
        vec_key_prime[i] = HIES::Decaps(pp, vec_dk[i], vec_ct[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average decryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    #ifdef DEBUG
    bool FLAG = true;  
    for(auto i = 0; i < TEST_NUM; i++){
        if (vec_key[i] != vec_key_prime[i]){
            std::cout << "enc/dec test fails" << std::endl;
            FLAG = false;
            break; 
        }
    }
    if (FLAG){
        std::cout << "enc/dec test succeeds" << std::endl;    
    }
    #endif


    // sign a message
    std::string msg = "good luck 2022";
    std::vector<HIES::SK> vec_sig(TEST_NUM); 

    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        vec_sig[i] = HIES::Sign(pp, vec_sk[i], msg);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average signing takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); 
    FLAG = true;
    for(auto i = 0; i < TEST_NUM; i++){
        if(HIES::Verify(pp, vec_pk[i], msg, vec_sig[i]) == false){
            std::cout << "sign/verify test fails" << std::endl;
            FLAG = false;
            break;
        } 
    }
    if(FLAG == true){
        std::cout << "sign/verify test succeeds" << std::endl;    
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


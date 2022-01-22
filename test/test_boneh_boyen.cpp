#define DEBUG

#include "../common/print.hpp"
#include "../hies/boneh-boyen-hibe.hpp"

int main()
{
    Print_SplitLine('-'); 
    std::cout << "*** Boneh-Boyen HIBE ***" << std::endl;
    Print_SplitLine('-'); 

    int TEST_NUM = 3000; 

    long seed = time(NULL); // initialize the seed with current system time
    srand(time(NULL));

    // generate global pp
    BB1::PP pp = BB1::Setup(); 

    // generate mpk and msk
    G2 mpk; 
    BB1::SK msk;
     
    std::tie(mpk, msk) = BB1::KeyGen(pp); 
    std::vector<std::string> id = {"CAS", "IIE", "SKLOIS"};
    //std::vector<std::string> id = {"CAS"};
    BB1::SK sk = BB1::Extract(pp, msk, id);  

    GT key, key_prime;
    BB1::CT ct;

    std::tie(ct, key) = BB1::Encaps(pp, mpk, id); 

    //std::cout << "key = " << key << std::endl;

    key_prime = BB1::Decaps(sk, ct); 

    //std::cout << "key' = " << key_prime << std::endl;

    #ifdef DEBUG 
    if (key == key_prime){
        std::cout << "enc/dec test succeeds" << std::endl;
    }
    else{
        std::cout << "enc/dec test fails" << std::endl;    
    }
    #endif

    return 0; 
}


/****************************************************************************
this hpp implements Schnorr CPK's signature component: Schnorr Signature
*****************************************************************************
* @author     Yu Chen
* @paper      HISE
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#include <cstdlib>
#include <ctime>
#include <iostream>
#include <mcl/ec.hpp>

typedef mcl::FpT<mcl::FpTag, 256> Fp;
typedef mcl::FpT<mcl::ZnTag, 256> Fr;
typedef mcl::EcT<Fp> Ec;

struct Schnorr_PP
{
    Ec g; 
};

struct Schnorr_SIG
{
    Ec A; 
    Fr z;
};

void Schnorr_Setup(Schnorr_PP& pp)
{
    mcl::initCurve<Ec, Fr>(MCL_SECP256K1, &pp.g);  

    #ifdef LOG 
        std::cout << "pp.g = " << pp.g << std::endl;
    #endif
}


void Schnorr_KeyGen(const Schnorr_PP& pp, Ec& pk, Fr& sk)
{
    sk.setRand();  
    Ec::mul(pk, pp.g, sk); // pk = g^sk

    #ifdef LOG 
        std::cout << "pk = " << pk << std::endl;
        std::cout << "sk = " << sk << std::endl;
    #endif
}

void Schnorr_Sign(const Schnorr_PP& pp, const Fr& sk, std::string& msg, Schnorr_SIG& sig)
{   
    Fr a; 
    a.setRand(); 
    Ec::mul(sig.A, pp.g, a); // A = g^a 
    
    std::string transcript = sig.A.getStr()+msg; 
    Fr e; 
    e.setHashOf(transcript.c_str(), transcript.length()); // e = H(A||m)

    Fr::mul(sig.z, e, a); 
    Fr::add(sig.z, sk, sig.z); // z = sk + ea

    #ifdef LOG 
        cout << "message = " << msg << endl;
        cout << "sig.A = " << sig.A << endl;
        cout << "sig.z = " << sig.z << endl;
    #endif 
}

void Schnorr_Verify(const Schnorr_PP& pp, const Ec& pk, std::string& msg, const Schnorr_SIG& sig)
{
    std::string transcript_str = sig.A.getStr() + msg; 
    Fr e; 
    e.setHashOf(transcript_str.c_str(), transcript_str.length()); // e = H(A||m)
    
    Ec LEFT, RIGHT; 
    Ec::mul(LEFT, pp.g, sig.z); // LEFT = g^z
    Ec::mul(RIGHT, sig.A, e); 
    Ec::add(RIGHT, RIGHT, pk); // RIGHT = pk A^e
    
    #ifdef LOG 
        if (LEFT == RIGHT) std::cout << "signature is valid" << std::endl; 
        else std::cout << "signature is invalid" << std::endl; 
    #endif
}

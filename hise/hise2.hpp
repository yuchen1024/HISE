/****************************************************************************
this hpp implements HISE from ElGamal PKE
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

struct HISE_PP
{
	Ec g; 
};

struct HISE_CT
{
	Ec X; 
	Ec Y;
};

void HISE_Setup(HISE_PP& pp)
{
    mcl::initCurve<Ec, Fr>(MCL_SECP256K1, &pp.g); 

	#ifdef LOG 
		std::cout << "pp.g = " << pp.g << std::endl;
	#endif
}


void HISE_KeyGen(const HISE_PP& pp, Ec& pk, std::string& sk)
{
	sk = "master secret key";
	Fr dk; 
	dk.setHashOf(sk.c_str(), sk.length()); // dk = H(sk)
	Ec::mul(pk, pp.g, dk); // pk = g^dk

	#ifdef LOG
		std::cout << "pk = " << pk << std::endl;
		std::cout << "sk = " << sk << std::endl;
	#endif
}


void HISE_Derive(std::string& sk, Fr& dk)
{
	dk.setHashOf(sk.c_str(), sk.length()); // dk = H(sk)
}

void HISE_Encrypt(const HISE_PP& pp, const Ec& pk, const Ec& pt, HISE_CT& ct)
{	
	Fr r; 
	r.setRand(); 
	Ec::mul(ct.X, pp.g, r); // X = g^r
	Ec::mul(ct.Y, pk, r);   // Y = pk^r
	Ec::add(ct.Y, ct.Y, pt); // Y = pk^r \cdot M

	#ifdef LOG 
		std::cout << "pt = " << pt << std::endl;
		std::cout << "ct.X = " << ct.X << std::endl;
		std::cout << "ct.Y = " << ct.Y << std::endl;
	#endif 
}

void HISE_Decrypt(const Fr& dk, const HISE_CT& ct, Ec& pt)
{
	Ec k; 	
	Ec::mul(k, ct.X, dk); // k = X^dk
	Ec::sub(pt, ct.Y, k); // m = Y-k
	
	#ifdef LOG 
		std::cout << "pt = " << pt << std::endl; 
	#endif
}

void HISE_Sign(std::string& sk, std::string& msg)
{
	//to do with the help of NIZKPoK
}





/****************************************************************************
this hpp implements CPK's encryption component: ElGamal PKE
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

struct ElGamal_PP
{
	Ec g; 
};

struct ElGamal_CT
{
	Ec X; 
	Ec Y;
};

void ElGamal_Setup(ElGamal_PP& pp)
{
    mcl::initCurve<Ec, Fr>(MCL_SECP256K1, &pp.g);  

	#ifdef LOG 
		std::cout << "pp.g = " << pp.g << std::endl;
	#endif
}


void ElGamal_KeyGen(const ElGamal_PP& pp, Ec& pk, Fr& sk)
{
	sk.setRand(); 
	Ec::mul(pk, pp.g, sk); // pk = g^sk

	#ifdef LOG 
		std::cout << "pk = " << pk << std::endl;
		std::cout << "sk = " << sk << std::endl;
	#endif
}

void ElGamal_Encrypt(const ElGamal_PP& pp, const Ec& pk, const Ec& pt, ElGamal_CT& ct)
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

void ElGamal_Decrypt(const Fr& sk, const ElGamal_CT& ct, Ec& pt)
{
	Ec k; 	
	Ec::mul(k, ct.X, sk); // k = X^dk
	Ec::sub(pt, ct.Y, k); // m = Y-k
	
	#ifdef LOG 
		std::cout << "pt = " << pt << std::endl; 
	#endif
}

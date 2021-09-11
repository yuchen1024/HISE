/****************************************************************************
this hpp implements global escrow PKE 
(derive from a variant of Joux's 3-party NIKE)
relies on more efficient asymmetric pairing
*****************************************************************************
* @author     Yu Chen
* @paper      HISE
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#include <cstdlib>
#include <ctime>
#include <iostream>

#include <mcl/bls12_381.hpp>

using namespace mcl::bls12;


struct Global_Escrow_PKE_PP
{
	G1 g1; 
	G2 g2; 
	G1 epk1;
	G2 epk2;  
};

struct Global_Escrow_PKE_CT
{
	G2 X; 
	GT Y;
	G1 receiver_pk; 
};

void Global_Escrow_PKE_Setup(Global_Escrow_PKE_PP& pp, Fr& esk)
{
	// setup pairing
    initPairing();
	// pick two random generators
	mapToG1(pp.g1, rand());
	mapToG2(pp.g2, rand()); 
 
	esk.setRand(); 
	G1::mul(pp.epk1, pp.g1, esk); // epk1 = g1^esk
	G2::mul(pp.epk2, pp.g2, esk); // epk2 = g2^esk

	#ifdef DEBUG 
		std::cout << "pp.g1 = " << pp.g1 << std::endl;
		std::cout << "pp.g2 = " << pp.g2 << std::endl;
		std::cout << "pp.epk1 = " << pp.epk1 << std::endl; 
		std::cout << "pp.epk2 = " << pp.epk2 << std::endl; 
		std::cout << "esk = " << esk << std::endl; 
	#endif
}


void Global_Escrow_PKE_KeyGen(const Global_Escrow_PKE_PP& pp, G1& pk, Fr& sk)
{ 
	sk.setRand(); 
	G1::mul(pk, pp.g1, sk); // pk = g1^sk

	#ifdef DEBUG 
		std::cout << "pk = " << pk << std::endl;
		std::cout << "sk = " << sk << std::endl;
	#endif
}


void Global_Escrow_PKE_Encrypt(Global_Escrow_PKE_PP& pp, const G1& pk, const GT& pt, Global_Escrow_PKE_CT& ct)
{	
	Fr r; 
	r.setRand(); 
	G2::mul(ct.X, pp.g2, r); // X = g2^r

	GT k; 
	pairing(k, pk, pp.epk2); // h1 = e(pk_beta, epk2)

	GT::pow(k, k, r); // k = k^r 

	GT::mul(ct.Y, k, pt);    // Y = k \cdot m

	ct.receiver_pk = pk; 
	#ifdef DEBUG 
		std::cout << "pt = " << pt << std::endl;
		std::cout << "ct.X = " << ct.X << std::endl;
		std::cout << "ct.Y = " << ct.Y << std::endl;
	#endif 
}

void Global_Escrow_PKE_Decrypt(Global_Escrow_PKE_PP& pp, Fr& sk, Global_Escrow_PKE_CT& ct, GT& pt)
{	
	GT k; 
	pairing(k, pp.epk1, ct.X); // k = e(epk1, X)
	GT::pow(k, k, sk); 
	GT::div(pt, ct.Y, k); 

	#ifdef DEBUG 
		std::cout << "pt = " << pt << std::endl; 
	#endif
}

void Global_Escrow_PKE_Escrow_Decrypt(Global_Escrow_PKE_PP& pp, Fr& esk, Global_Escrow_PKE_CT& ct, GT& pt)
{
	GT k; 
	pairing(k, ct.receiver_pk, ct.X); // k = e(pk_\beta, X)
	GT::pow(k, k, esk); 
	GT::div(pt, ct.Y, k); 

	#ifdef DEBUG 
		std::cout << "pt = " << pt << std::endl; 
	#endif
}

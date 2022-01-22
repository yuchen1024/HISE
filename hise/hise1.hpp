/****************************************************************************
this hpp implements CPA-secure HISE from Boneh-Franklin IBE scheme
*****************************************************************************
* @author     Yu Chen
* @paper      HISE
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#include <cstdlib>
#include <ctime>
#include <iostream>
#include <mcl/bls12_381.hpp>

#include "../utility/hash.hpp"

struct HISE_PP
{
	G1 g1; 
	G2 g2; 
	std::string id; // id^*
};

struct HISE_CT
{
	G1 X; 
	GT Y;
};

void HISE_Setup(HISE_PP& pp)
{
    // setup pairing
    initPairing();

	// pick two random generators
	mapToG1(pp.g1, rand());
	mapToG2(pp.g2, rand()); 

	pp.id.assign(33, '1'); // set id^* = 1^33

	#ifdef LOG 
		std::cout << "pp.g1 = " << pp.g1 << std::endl;
		std::cout << "pp.g2 = " << pp.g2 << std::endl;
	#endif
}


void HISE_KeyGen(const HISE_PP& pp, G1& pk, Fr& sk)
{
	sk.setRand(); 
	G1::mul(pk, pp.g1, sk); // pk = g1^sk

	#ifdef DEBUG 
		std::cout << "pk = " << pk << std::endl;
		std::cout << "sk = " << sk << std::endl;
	#endif
}


void HISE_Derive(const HISE_PP& pp, const Fr& sk, G2& dk)
{
	G2 hash_id; 
	HashToG2(hash_id, pp.id);
	G2::mul(dk, hash_id, sk); // dk = hash_id^sk
}

void HISE_Encrypt(const HISE_PP& pp, const G1& pk, const GT& pt, HISE_CT& ct)
{	
	Fr r; 
	r.setRand(); 
	G1::mul(ct.X, pp.g1, r); // ciphertext = g1^r
	G2 hash_id; 
	HashToG2(hash_id, pp.id);
	GT k; 
	G2::mul(hash_id, hash_id, r); 
	pairing(k, pk, hash_id); 
	//Fp12::pow(k, k, r); // k = e(pk, hash_id)^r 
	GT::mul(ct.Y, k, pt);       // Y = k \cdot m 

	#ifdef LOG 
		std::cout << "pt = " << pt << endl;
		std::cout << "ct.X = " << ct.X << endl;
		std::cout << "ct.Y = " << ct.Y << endl;
	#endif 
}

void HISE_Decrypt(const G2& dk, const HISE_CT& ct, GT& pt)
{
	GT k; 	
	
	pairing(k, ct.X, dk); // k = e(X, dk)
	GT::div(pt, ct.Y, k); // m = Y/k
	
	#ifdef DEBUG 
		std::cout << "pt = " << pt << std::endl; 
	#endif
}

void HISE_Sign(const Fr& sk, const std::string& msg, G2& sig)
{
	G2 hash_msg; 
	HashToG2(hash_msg, '0' + msg);  // hash_msg = H(0|m)
	G2::mul(sig, hash_msg, sk); // SIGMA = hash_msg^sk
}

void HISE_Verify(const HISE_PP& pp, const G1& pk, const std::string& msg, G2& sig)
{
	GT LEFT, RIGHT; 
	G2 hash_msg; 
	HashToG2(hash_msg, '0' + msg);

	pairing(LEFT, pk, hash_msg); 
	pairing(RIGHT, pp.g1, sig); 

	#ifdef DEBUG 	
	if (LEFT == RIGHT){
		std::cout << "signature is valid" << std::endl;  
	}
	else{
		std::cout << "signature is invalid" << std::endl; 
	}
	#endif
}


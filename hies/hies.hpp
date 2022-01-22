/****************************************************************************
this hpp implements CPA-secure HIES scheme
*****************************************************************************
* @author     Yu Chen
* @paper      HIES
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#include <cstdlib>
#include <ctime>
#include <iostream>
#include <string>
#include <vector>
#include <mcl/bls12_381.hpp>

#include "../utility/hash.hpp"

namespace HIES{

struct PP
{
	G1 g1; 
	G2 g2; 
	std::string id0; 
	std::string id1;
};

struct SK
{
	G1 d0; 
	std::vector<G2> vec_d; 
};

struct CT
{
	G2 B;
	std::vector<G1> vec_C;
};

PP Setup()
{
    // setup pairing
    initPairing();

	PP pp; 
	// pick two random generators
	mapToG1(pp.g1, rand());
	mapToG2(pp.g2, rand());
	pp.id0.assign(32, '0'); // set id0^* = 0^32
	pp.id1.assign(32, '1'); // set id1^* = 1^32 
	return pp;  
}


std::tuple<G2, SK> KeyGen(const PP& pp)
{
	Fr alpha; 
	alpha.setRand(); 
	SK dk; 
	G1::mul(dk.d0, pp.g1, alpha); // msk = g1^alpha

	G2 pk; 
	G2::mul(pk, pp.g2, alpha); // mpk = g2^alpha

	return {pk, dk}; 
}

SK Derive(PP pp, SK dk)
{
	G1 hash_id;
	Fr r;  

	SK sk = dk; 
	
	r.setRand(); 
	HashToG1(hash_id, "0" + pp.id1);
	G1::mul(hash_id, hash_id, r); 
	G1::add(sk.d0, sk.d0, hash_id);  
	G2 temp; 
	G2::mul(temp, pp.g2, r); 
	sk.vec_d.emplace_back(temp); 

	return sk; 
}


std::tuple<CT, GT> Encaps(const PP& pp, const G2& pk)
{	
	CT ct; 
	Fr s;
	s.setRand();
	GT key;  
	pairing(key, pp.g1, pk);  
	GT::pow(key, key, s);
	G2::mul(ct.B, pp.g2, s); 
	ct.vec_C.resize(1); 
	
	HashToG1(ct.vec_C[0], "0" + pp.id0);
	G1::mul(ct.vec_C[0], ct.vec_C[0], s);
	
	return {ct, key};

}

GT Decaps(const PP& pp, const SK& dk, const CT& ct)
{
	//compute the real dk
	SK real_dk = dk; 
	G1 hash_id;
	Fr r;  	
	r.setRand(); 
	HashToG1(hash_id, "0" + pp.id0);
	G1::mul(hash_id, hash_id, r); 
	G1::add(real_dk.d0, real_dk.d0, hash_id);  
	G2 temp; 
	G2::mul(temp, pp.g2, r); 
	real_dk.vec_d.emplace_back(temp); 
	
	GT denominator; 

	pairing(denominator, ct.vec_C[0], real_dk.vec_d[0]);

	GT numerator; 
	pairing(numerator, real_dk.d0, ct.B); 
 
	GT key; 
	GT::div(key, numerator, denominator); 

	return key; 
}

SK Sign(const PP& pp, const SK& sk, std::string &msg)
{
	SK sigma = sk; 
	G1 hash_msg;
	Fr r; 
	r.setRand(); 
	HashToG1(hash_msg, "1" + msg);
	G1::mul(hash_msg, hash_msg, r); 
	G1::add(sigma.d0, sigma.d0, hash_msg); 
	G2 temp; 
	G2::mul(temp, pp.g2, r);
	sigma.vec_d.emplace_back(temp);  

	return sigma; 
}

bool Verify(const PP& pp, const G2& pk, const std::string &msg, const SK &sigma)
{
	GT LEFT, L1, L2, L3;

	pairing(L1, pp.g1, pk); 
	G1 hash_id, hash_msg; 
	HashToG1(hash_id, "0" + pp.id1);
	HashToG1(hash_msg, "1" + msg);
	pairing(L2, hash_id, sigma.vec_d[0]); 
	pairing(L3, hash_msg, sigma.vec_d[1]);
	GT::mul(LEFT, L1, L2); 
	GT::mul(LEFT, LEFT, L3);  

	GT RIGHT; 
	pairing(RIGHT, sigma.d0, pp.g2); 

	if (LEFT == RIGHT){
		//std::cout << "signature is valid" << std::endl;  
		return true; 
	}
	else{
		//std::cout << "signature is invalid" << std::endl; 
		return false; 
	}
}

}





/****************************************************************************
this hpp implements a variant of Boneh-Boyen HIBE in ROM
*****************************************************************************
* @author     Yu Chen
* @paper      HIES
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#include <cstdlib>
#include <ctime>
#include <iostream>
#include <mcl/bls12_381.hpp>

#include "../utility/hash.hpp"



namespace BB1{

struct PP
{
	G1 g1; 
	G2 g2; 
};

struct SK
{
	G1 d0; 
	std::vector<G2> vec_d; 
	std::vector<std::string> id; 
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
	return pp;  
}


std::tuple<G2, SK> KeyGen(const PP& pp)
{
	Fr alpha; 
	alpha.setRand(); 
	SK msk; 
	G1::mul(msk.d0, pp.g1, alpha); // msk = g1^alpha

	G2 mpk; 
	G2::mul(mpk, pp.g2, alpha); // mpk = g2^alpha

	return {mpk, msk}; 
}


SK Extract(PP pp, SK sk, std::vector<std::string>& id)
{
	size_t l = id.size(); 
	std::vector<G1> vec_hash_id(l);
	std::vector<Fr> vec_r(l);  

	SK delegate_sk = sk; 
	for(auto i = 0; i < l; i++){
		vec_r[i].setRand(); 
		HashToG1(vec_hash_id[i], std::to_string(i) + id[i]);
		G1::mul(vec_hash_id[i], vec_hash_id[i], vec_r[i]); 
		G1::add(delegate_sk.d0, delegate_sk.d0, vec_hash_id[i]); 
		delegate_sk.id.emplace_back(id[i]); 
		G2 temp; 
		G2::mul(temp, pp.g2, vec_r[i]); 
		delegate_sk.vec_d.emplace_back(temp); 
	}

	return delegate_sk; 
}

std::tuple<CT, GT> Encaps(const PP& pp, const G2& mpk, std::vector<std::string>& id)
{	
	CT ct; 
	Fr s;
	s.setRand();
	GT key;  
	pairing(key, pp.g1, mpk);  
	GT::pow(key, key, s);
	G2::mul(ct.B, pp.g2, s); 
	size_t l = id.size();
	ct.vec_C.resize(l); 
	for(auto i = 0; i < l; i++){
		HashToG1(ct.vec_C[i], std::to_string(i) + id[i]);
		G1::mul(ct.vec_C[i], ct.vec_C[i], s);
	}
	return {ct, key};

}

GT Decaps(const SK& sk, const CT& ct)
{
	if(ct.vec_C.size() != sk.id.size()){
		std::cerr << "the size of sk_id and ct do not match" << std::endl;
	}
	GT denominator; 
	pairing(denominator, ct.vec_C[0], sk.vec_d[0]);
	for(auto i = 1; i < sk.id.size(); i++){
		GT temp; 
		pairing(temp, ct.vec_C[i], sk.vec_d[i]); 
		GT::mul(denominator, denominator, temp); 
	}
	GT numerator; 
	pairing(numerator, sk.d0, ct.B); 
 
	GT key; 
	GT::div(key, numerator, denominator); 
	return key; 
}

}





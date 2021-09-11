/****************************************************************************
this hpp implements global escrow HISE1 (HISE1 + twisted Naor-Yung paradigm)
*****************************************************************************
* @author     Yu Chen
* @paper      HISE
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#include <mcl/bls12_381.hpp>
#include <cstdlib>
#include <ctime>
#include <iostream>

using namespace mcl::bls12;

/* hash a string to a G2 point*/
void HashToG2(G2& P, const std::string& str)
{
	hashAndMapToG2(P, str.c_str(), str.length());
}


struct DDH_Instance
{
	G1 g, X; 
	GT h, Y; 
};

struct DDH_Witness
{
	Fr r; 
};

struct DDH_Proof
{
	G1 A1;
	GT A2;
	Fr z; 
};

/* generate a proof */
void NIZK_Prove(DDH_Instance &instance, DDH_Witness &witness, std::string &transcript_str, DDH_Proof &proof)
{
	Fr a; 
	a.setRand(); 
	G1::mul(proof.A1, instance.g, a); 
	GT::pow(proof.A2, instance.h, a); 
	
	transcript_str += proof.A1.getStr();
	transcript_str += proof.A2.getStr(); 
	Fr e; 
	e.setHashOf(transcript_str.c_str(), transcript_str.length());  

	Fr::mul(proof.z, e, witness.r); 
	Fr::add(proof.z, a, proof.z); // z = a + er
}

bool NIZK_Verify(DDH_Instance &instance, std::string &transcript_str, DDH_Proof &proof)
{	
	transcript_str += proof.A1.getStr();
	transcript_str += proof.A2.getStr(); 
	Fr e; 	
	e.setHashOf(transcript_str.c_str(), transcript_str.length());

	// check the first equation 
	G1 LEFT1;
	G1::mul(LEFT1, instance.g, proof.z); 

	G1 RIGHT1; 
	G1::mul(RIGHT1, instance.X, e); 
	G1::add(RIGHT1, RIGHT1, proof.A1); 


	// check the second equation
	GT LEFT2; 
	GT::pow(LEFT2, instance.h, proof.z); 

	GT RIGHT2; 
	GT::pow(RIGHT2, instance.Y, e); 
	GT::mul(RIGHT2, RIGHT2, proof.A2); 

	#ifdef LOG
		std::cout << "LEFT1 = " << LEFT1 << std::endl; 
		std::cout << "RIGHT1 = " << RIGHT1 << std::endl; 
		std::cout << "LEFT2 = " << LEFT2 << std::endl; 
		std::cout << "RIGHT2 = " << RIGHT2 << std::endl; 
	#endif

	bool V1 = (LEFT1 == RIGHT1); 
	bool V2 = (LEFT2 == RIGHT2);
	bool Validity = V1 && V2; 	

    #ifdef DEBUG
    Print_SplitLine('-'); 
    std::cout << "verify the NIZKPoK for DDH >>>" << std::endl; 
    std::cout << std::boolalpha << "Condition 1 (DDH proof) = " << V1 << std::endl; 
    std::cout << std::boolalpha << "Condition 2 (DDH proof) = " << V2 << std::endl; 
    #endif

	return Validity; 
}

struct Global_Escrow_HISE_PP
{
	G1 g1; 
	G2 g2; 
	G1 epk; 
	std::string id; // id^*
};

struct Global_Escrow_HISE_CT
{
	G1 receiver_pk;

	G1 X; 
	GT Y1;
	GT Y2; // raw ciphertext 
	G1 A1; 
	GT A2; 
	Fr z;    // consistency proof
};

void Global_Escrow_HISE_Setup(Global_Escrow_HISE_PP& pp, G2& esk)
{
	// setup pairing
    initPairing();
	// pick two random generators
	mapToG1(pp.g1, rand());
	mapToG2(pp.g2, rand()); 

	pp.id.assign(33, '1'); // set id^* = 1^33

	Fr s; 
	s.setRand(); 
	G1::mul(pp.epk, pp.g1, s); // epk = g1^s

	G2 hash_id; 
	HashToG2(hash_id, pp.id);
	G2::mul(esk, hash_id, s); // esk = hash_id^s

	#ifdef LOG 
		std::cout << "pp.g1 = " << pp.g1 << std::endl;
		std::cout << "pp.g2 = " << pp.g2 << std::endl;
		std::cout << "pp.epk = " << pp.epk << std::endl; 
		std::cout << "pp.id = " << pp.id << std::endl; 
		std::cout << "esk = " << esk << std::endl; 
	#endif
}


void Global_Escrow_HISE_KeyGen(const Global_Escrow_HISE_PP& pp, G1& pk, Fr& sk)
{
	sk.setRand(); 
	G1::mul(pk, pp.g1, sk); // pk = g1^sk

	#ifdef LOG 
		std::cout << "pk = " << pk << std::endl;
		std::cout << "sk = " << sk << std::endl;
	#endif
}


void Global_Escrow_HISE_Derive(const Global_Escrow_HISE_PP& pp, const Fr& sk, G2& dk)
{
	G2 hash_id; 
	HashToG2(hash_id, pp.id);
	G2::mul(dk, hash_id, sk); // dk = hash_id^sk
}

void Global_Escrow_HISE_Encrypt(const Global_Escrow_HISE_PP& pp, const G1& pk, const GT& pt, Global_Escrow_HISE_CT& ct)
{	
	ct.receiver_pk = pk; 

	Fr r; 
	r.setRand(); 
	G1::mul(ct.X, pp.g1, r); // X = g1^r
	G2 hash_id; 
	HashToG2(hash_id, pp.id);

	GT h, h1, h2; 
	pairing(h1, pk, hash_id); // h1 = e(pk, H(id))
	pairing(h2, pp.epk, hash_id); // h2 = e(epk, H(id)) 

	GT k1, k2; 
	GT::pow(k1, h1, r); // k1 = h1^r 
	GT::pow(k2, h2, r); // k2 = h2^r 

	GT::mul(ct.Y1, k1, pt);       // Y1 = k1 \cdot m
	GT::mul(ct.Y2, k2, pt);       // Y2 = k2 \cdot m

	DDH_Instance instance; 
	instance.g = pp.g1; 
	instance.X = ct.X; 
	GT::div(instance.h, h1, h2); 
	GT::div(instance.Y, ct.Y1, ct.Y2); 

	DDH_Witness witness; 
	witness.r = r; 

	DDH_Proof proof;

	std::string transcript_str = ""; 
	NIZK_Prove(instance, witness, transcript_str, proof); 

	ct.A1 = proof.A1; 
	ct.A2 = proof.A2;
	ct.z  = proof.z; 

	#ifdef LOG 
		std::cout << "pt = " << pt << std::endl;
		std::cout << "ct.X = " << ct.X << std::endl;
		std::cout << "ct.Y1 = " << ct.Y1 << std::endl;
		std::cout << "ct.Y2 = " << ct.Y2 << std::endl;
		std::cout << "ct.A1 = " << ct.A1 << std::endl;
		std::cout << "ct.A2 = " << ct.A2 << std::endl;
		std::cout << "ct.z = " << ct.z << std::endl;
	#endif 
}

void Global_Escrow_HISE_Decrypt(Global_Escrow_HISE_PP& pp, G2& dk, Global_Escrow_HISE_CT& ct, GT& pt)
{
	G2 hash_id; 
	HashToG2(hash_id, pp.id);
	
	DDH_Instance instance; 
	instance.g = pp.g1; 
	instance.X = ct.X; 
	GT h1, h2; 
	pairing(h1, ct.receiver_pk, hash_id); // h1 = e(pk, H(id))
	pairing(h2, pp.epk, hash_id); // h2 = e(epk, H(id)) 
	GT::div(instance.h, h1, h2); 
	GT::div(instance.Y, ct.Y1, ct.Y2); 

	std::string transcript_str; 

	DDH_Proof proof; 
	proof.A1 = ct.A1;
	proof.A2 = ct.A2; 
	proof.z  = ct.z; 


	if (NIZK_Verify(instance, transcript_str, proof) == false){
		std::cout << "ciphertext is invalid" << std::endl; 
	}

	else{
		GT k; 	
		pairing(k, ct.X, dk); // k = e(X, dk)
		GT::div(pt, ct.Y1, k); // m = Y/k
	
		#ifdef LOG
			std::cout << "pt = " << pt << std::endl; 
		#endif
	}
}

void Global_Escrow_HISE_Escrow_Decrypt(Global_Escrow_HISE_PP& pp, G2& esk, Global_Escrow_HISE_CT& ct, GT& pt)
{
	G2 hash_id; 
	HashToG2(hash_id, pp.id);
	
	DDH_Instance instance; 
	instance.g = pp.g1; 
	instance.X = ct.X; 
	GT h1, h2; 
	pairing(h1, ct.receiver_pk, hash_id); // h1 = e(pk, H(id))
	pairing(h2, pp.epk, hash_id); // h2 = e(epk, H(id)) 
	GT::div(instance.h, h1, h2); 
	GT::div(instance.Y, ct.Y1, ct.Y2); 

	std::string transcript_str; 

	DDH_Proof proof; 
	proof.A1 = ct.A1;
	proof.A2 = ct.A2; 
	proof.z  = ct.z; 


	if (NIZK_Verify(instance, transcript_str, proof) == false){
		std::cout << "ciphertext is invalid" << std::endl; 
	}

	else{
		GT k; 	
		pairing(k, ct.X, esk); // k = e(X, dk)
		GT::div(pt, ct.Y2, k); // m = Y/k
	
		#ifdef LOG 
			std::cout << "pt = " << pt << std::endl; 
		#endif
	}
}

void Global_Escrow_HISE_Sign(const Fr& sk, const std::string& msg, G2& sig)
{
	G2 hash_msg; 
	HashToG2(hash_msg, '0' + msg);  // hash_msg = H(0|m)
	G2::mul(sig, hash_msg, sk); // sig = hash_msg^sk
}

void Global_Escrow_HISE_Verify(const Global_Escrow_HISE_PP& pp, const G1& pk, const std::string& msg, G2& sig)
{
	Fp12 LEFT, RIGHT; 
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


/****************************************************************************
this hpp implements global escrow PKE from ElGamal PKE and case-tailored NIKE
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


struct Global_Escrow_PKE_PP
{
	Ec g; 
	Ec epk; 
};

struct Global_Escrow_PKE_CT
{
	Ec pk; 
	Ec X; 
	Ec Y1;
	Ec Y2;

	Ec A1; 
	Ec A2; 
	Fr z; 
};


struct DDH_Instance{
	Ec g1, h1, g2, h2; 
};

struct DDH_Witness{
	Fr r; 
};

struct DDH_Proof{
	Ec A1, A2; 
	Fr z; 
};



/* generate a proof */
void NIZK_Prove(DDH_Instance &instance, DDH_Witness &witness, std::string &transcript_str, DDH_Proof &proof)
{
	Fr a; 
	a.setRand(); 

	Ec::mul(proof.A1, instance.g1, a);
	Ec::mul(proof.A2, instance.g2, a);  
	
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
	Ec LEFT1;
	Ec::mul(LEFT1, instance.g1, proof.z); // g1^z 

	Ec RIGHT1; 
	Ec::mul(RIGHT1, instance.h1, e); 
	Ec::add(RIGHT1, RIGHT1, proof.A1); // A1 X^e


	// check the second equation
	Ec LEFT2; 
	Ec::mul(LEFT2, instance.g2, proof.z); 

	Ec RIGHT2; 
	Ec::mul(RIGHT2, instance.h2, e); 
	Ec::add(RIGHT2, RIGHT2, proof.A2); 

	bool Validity, V1, V2; 
	V1 = (LEFT1==RIGHT1); 
	V2 = (LEFT2==RIGHT2); 
	std::cout << std::boolalpha << "Condition 1 (DDH Proof) = " << V1 << std::endl; 
    std::cout << std::boolalpha << "Condition 2 (DDH Proof) = " << V2 << std::endl; 
	Validity = V1 && V2; 
		
	return Validity; 
}

void Global_Escrow_PKE_Setup(Global_Escrow_PKE_PP& pp, Fr& esk)
{ 
    mcl::initCurve<Ec, Fr>(MCL_SECP256K1, &pp.g); 
	esk.setRand(); 
	Ec::mul(pp.epk, pp.g, esk); 

	#ifdef DEBUG 
		std::cout << "pp.g = " << pp.g << std::endl;
		std::cout << "pp.epk = " << pp.epk << std::endl; 
	#endif
}


void Global_Escrow_PKE_KeyGen(Global_Escrow_PKE_PP& pp, Ec& pk, Fr& sk)
{
	sk.setRand(); 
	Ec::mul(pk, pp.g, sk); // pk = g^sk

	#ifdef DEBUG 
		std::cout << "pk = " << pk << std::endl;
		std::cout << "sk = " << sk << std::endl;
	#endif
}

void Global_Escrow_PKE_Encrypt(Global_Escrow_PKE_PP& pp, Ec& pk, Ec& pt, Global_Escrow_PKE_CT& ct)
{	
	Fr r; 
	r.setRand(); 
	Ec::mul(ct.X, pp.g, r); // X = g^r

	ct.pk = pk; 
	Ec::mul(ct.Y1, pk, r);   // Y1 = pk^r
	Ec::add(ct.Y1, ct.Y1, pt); // Y1 = pk^r \cdot M

	Ec::mul(ct.Y2, pp.epk, r);   // Y2 = epk^r
	Ec::add(ct.Y2, ct.Y2, pt); // Y2 = epk^r \cdot M

	DDH_Instance instance; 
	instance.g1 = pp.g; 
	instance.h1 = ct.X; 
	Ec::sub(instance.g2, pp.epk, ct.pk); 
	Ec::sub(instance.h2, ct.Y2, ct.Y1); 

	DDH_Witness witness; 
	witness.r = r; 

	std::string transcript_str = "";

	DDH_Proof proof; 

	NIZK_Prove(instance, witness, transcript_str, proof); 

	ct.A1 = proof.A1; 
	ct.A2 = proof.A2; 
	ct.z  = proof.z; 
}

void Global_Escrow_PKE_Decrypt(Global_Escrow_PKE_PP& pp, Fr& sk, Global_Escrow_PKE_CT& ct, Ec& pt_prime)
{
	DDH_Instance instance; 

	instance.g1 = pp.g; 
	instance.h1 = ct.X; 

	Ec::sub(instance.g2, pp.epk, ct.pk);   // h = epk - pk
	Ec::sub(instance.h2, ct.Y2, ct.Y1); // Y = Y2 - Y1

	std::string transcript_str = ""; 

	DDH_Proof proof; 
	proof.A1 = ct.A1; 
	proof.A2 = ct.A2; 
	proof.z  = ct.z; 

	if (NIZK_Verify(instance, transcript_str, proof) == false){
		std::cout << "ciphertext is invalid" << std::endl;
	}

	else{
		Ec k; 	
		Ec::mul(k, ct.X, sk); // k = X^sk
		Ec::sub(pt_prime, ct.Y1, k); // m = Y1-k
	
		#ifdef DEBUG 
			std::cout << "pt' = " << pt_prime << std::endl; 
		#endif
	} 
}

void Global_Escrow_PKE_Escrow_Decrypt(Global_Escrow_PKE_PP& pp, Fr& esk, Global_Escrow_PKE_CT& ct, Ec& pt_prime)
{
	DDH_Instance instance; 

	instance.g1 = pp.g; 
	instance.h1 = ct.X; 

	Ec::sub(instance.g2, pp.epk, ct.pk);   // h = epk - pk
	Ec::sub(instance.h2, ct.Y2, ct.Y1); // Y = Y2 - Y1

	std::string transcript_str = ""; 

	DDH_Proof proof; 
	proof.A1 = ct.A1; 
	proof.A2 = ct.A2; 
	proof.z  = ct.z; 

	if (NIZK_Verify(instance, transcript_str, proof) == false){
		std::cout << "ciphertext is invalid" << std::endl;
	}

	else{
		Ec k; 	
		Ec::mul(k, ct.X, esk); // k = X^sk
		Ec::sub(pt_prime, ct.Y2, k); // m = Y1-k
	
		#ifdef DEBUG 
			std::cout << "pt' = " << pt_prime << std::endl; 
		#endif
	}
}

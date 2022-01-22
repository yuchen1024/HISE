#ifndef UTILITY_HASH_HPP_
#define UTILITY_HASH_HPP_

#include <mcl/bls12_381.hpp>
#include <cstdlib>
#include <ctime>
#include <iostream>

using namespace mcl::bls12;

/* hash a string to a G1 point*/
void HashToG1(G1& P, const std::string& str)
{
	hashAndMapToG1(P, str.c_str(), str.length());
}

/* hash a string to a G2 point*/
void HashToG2(G2& P, const std::string& str)
{
	hashAndMapToG2(P, str.c_str(), str.length());
}

#endif
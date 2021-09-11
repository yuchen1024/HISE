/****************************************************************************
this hpp implements some routine algorithms
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef PRINT_HPP_
#define PRINT_HPP_

#include <iostream>

const int LINE_LEN = 120;     // the length of split line

/* print split line */
void Print_SplitLine(char ch)
{
    for (auto i = 0; i < LINE_LEN; i++) std::cout << ch;  
    std::cout << std::endl;
}

#endif
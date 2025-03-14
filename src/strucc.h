/*******************************************************************************

 * This notice, including the copyright notice and permission notice, 
 * must be retained in all copies or substantial portions of the Software and 
 * in all derivative works.
 *
 * Software Name: CryptoDbSS-Validator
 * Copyright (C) 2025 Steeven J Salazar.
 * License: CryptoDbSS: Software Review and Audit License
 * 
 * https://github.com/CryptoDbSS/CryptoDbSS-Validator
 *
 * IMPORTANT: Before using, compiling, or doing anything with this software,
 * you must read and accept the terms of the License provided with this software.
 *
 * If you do not have a copy of the License, you can obtain it at the following link:
 * https://github.com/CryptoDbSS/CryptoDbSS-Validator/blob/main/LICENSE.md
 *
 * By using, compiling, or modifying this software, you implicitly accept
 * the terms of the License. If you do not agree with the terms,
 * do not use, compile, or modify this software.
 * 
 * This software is provided "as is," without warranty of any kind.
 * For more details, see the LICENSE file.

********************************************************************************/


/* ********************************************************************************
 
    The CryptoDbSS, blockchain-core, consensus, protocols and misc.

    This software is a review and audit release, it should only be used for 
    development, testing, education and auditing purposes. 

    Third-party dependencies: CrowCpp, Crypto++, OpenSSL, Boost, ASIO, libcurl.

    questions, suggestions or contact : Steevenjavier@gmail.com

                                S.S

*********************************************************************************/

#ifndef STRUCC_H
#define STRUCC_H

#include "CryptoDbSS.cpp"


using namespace std;

struct dbstruct{
    bool indexed;
    bool indexing;
    mutex indexingmtx;
    uint64_t balance; 
    uint16_t DataCompressIndex;
};

struct Accsync{
    bool transacSync;
    bool indexed;
    bool indexing;
    bool indexedNumber;
    bool NumberCheck;
    uint16_t transacNumbrSync;
    uint64_t value;
    uint64_t valueAnt;
    uint16_t DataCompressIndex;
};

struct nodeStruct{
    
    string LoggedDataKey;
    bool logged;
    string ip;
    uint64_t lastblLocal;
    map<uint64_t,string> ShaMinProposal;

};

    
#endif


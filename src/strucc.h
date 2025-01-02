/*
 * Software Name: CryptoDbSS
 * Copyright (C) 2025 Steeven J Salazar.
 * License: CryptoDbSS: Software Review and Audit License
 * 
 * https://github.com/Steeven512/CryptoDbSS
 *
 * IMPORTANT: Before using, compiling or do anything with this software, 
 * you must read and accept the terms of this License.
 * 
 * This software is provided "as is," without warranty of any kind.
 * For more details, see the LICENSE file.
 */


/* 
 
The CryptoDbSS, blockchain-core, consensus, protocols and misc.

This software is a prototype version, it should only be used for 
development, testing, study and auditing proporses. 

Third-party dependencies: CrowCpp, Crypto++, OpenSSL, Boost, ASIO, libcurl.

questions, suggestions or contact : Steevenjavier@gmail.com

*/

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


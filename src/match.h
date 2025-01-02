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

#include <string>
#include <iostream>

using namespace std;

uint percent(unsigned long long value, uint ratio){

    unsigned long long product = (value * ratio ) /100000;

/*
    if ((10000*product)/ratio!=value){
        cout<<endl<<"se debe rellenar la suma"<<endl;
        //logica para ajusta cuenta

    }
*/
    return product;
    
}


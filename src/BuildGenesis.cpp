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

#ifndef MAKEBLOCK_H
#define MAKEBLOCK_H

#include <filesystem>
#include <fstream>
#include "key.h"
#include "codec.h"
#include "hasher.h"

using namespace std;


void addHexStringInVector(vector<unsigned char> &vec, string datatocodify){
    for (uint i = 0; i < datatocodify.length(); i += 2){
        vec.push_back(hexToUint8_t(datatocodify.substr(i, 2)));
    }
}

string vectorstring(vector<unsigned char> &vec){
    string msg = "";
    for (unsigned int i = 0; i < vec.size(); i++){
        msg += byteToHex(vec[i]);
    }
    return msg;
}

string SHAstg(string stg){

    for (auto &c:stg){c=toupper(c);}
    vector<uint8_t> hashed = sha3_256(stg);
    string data66 =  vectorstring(hashed);
    for (auto &c:data66){c=toupper(c);}
    return data66;
    
}

int main(){

    const string idblockchainName = "CDB256SS::TEST-BLOCKCHAIN";
    std::string priv = "19FF43791854931E1DF41A8B572F26C172D09E78C1F67BDAC6921C741018FAF7";
    std::string to = "04622eae384a8c24ccfe8714d06987cef406bc7e5266594d26da2bb761d6d23fc198beb4328d76c63a31bd37615d0aa4abb449067b8676564f848bf0ca50b94bde";

    
    vector<unsigned char> IdBlkchain = sha3_256v(string_to_bytes(idblockchainName));
    string idBlckchn = vectorstring(IdBlkchain);

    std::string priv = "19FF43791854931E1DF41A8B572F26C172D09E78C1F67BDAC6921C741018FAF7";
    std::string to = "04622eae384a8c24ccfe8714d06987cef406bc7e5266594d26da2bb761d6d23fc198beb4328d76c63a31bd37615d0aa4abb449067b8676564f848bf0ca50b94bde";

    //value format 256,000,000.00000;
    // 1.00000 = 1
    
    uint64_t value = 25600000000000;
    vector<unsigned char> byteArray;

    //percent feed of %1.0 || x0.10 = 100
    uint feed = 0;

    if (priv.length() != 64) { 
		cout<<endl<<"invalid priv key length"<<endl;
		return 1;
	}
    if (to.length() != 130) { 
		cout<<endl<<"invalid public key length"<<endl;
		return 1;
	}

    std::string pubk = derivate(priv);
    
    for (auto& c : pubk) {c = std::toupper(c);}
    for (auto& s : to) {s = std::toupper(s);}
    
    string data = "00"+pubk.substr(2, 128)+ullToHex(0)+to.substr(2, 128)+ullToHex(value)+"0001"+uint32ToHex(feed);

    string blckheader = idBlckchn+idBlckchn+SHAstg(pubk.substr(2, 128));

    for (auto &s : data){s = toupper(s);}
    
	
    string sign = Signer(priv, data+blckheader);

    addHexStringInVector(byteArray,  idBlckchn);
    addHexStringInVector(byteArray, "01");
    addHexStringInVector(byteArray,idBlckchn);
    addHexStringInVector(byteArray, SHAstg(to.substr(2, 128)));    
    addHexStringInVector(byteArray, to.substr(2, 128));
    addHexStringInVector(byteArray, ullToHex(value));
    addHexStringInVector(byteArray, ullToHex(0));
    addHexStringInVector(byteArray, uint16ToHex(1));

    addHexStringInVector(byteArray,  data+sign); //

    addHexStringInVector(byteArray, "9696"); //end of blocks

    vector<unsigned char>blRefactHashed = sha3_256v(byteArray);

    for (uint8_t i = 0; i <blRefactHashed.size();i++){
        byteArray.push_back(blRefactHashed[i]);
    }


    ofstream filew2("blocks/0", ios::binary | ios::out);
    
    
    if(!filew2){
		cout<<endl<<"Fail Writing Genesis Block."<<endl;
		return 1;
	}
	
	
    for (unsigned int i = 0; i < byteArray.size(); i ++) {
        filew2.seekp(i);  
        filew2.put(byteArray[i]);
    }
    filew2.close();
    
    cout<<endl<<"Genesis Block Writed."<<endl;

    return 0;
       

}
#endif

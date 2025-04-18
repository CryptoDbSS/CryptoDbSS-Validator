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

#ifndef SETNOD_H
#define SETNOD_H

#include "CryptoDbSS.cpp"

vector<uint8_t> readFile(const std::string& filename);
void addHexStringInVector(vector<unsigned char> &vec, string datatocodify);

extern const uint16_t maxblksize;

int maxblks(){
    vector<uint8_t> v = readFile("sets/trxbl");
    string blockread = "";
    for (unsigned int i = 0; i < v.size(); i++){

        blockread += byteToHex(v[i]);
    }
    return hexToUint(blockread);
}

bool setmaxblks(int x){

    vector<unsigned char> byteArray;
    if(x>maxblksize){
        cout<<endl<<"error setmaxblk x>maxblksize"<<endl;
        return false;
    }
    string xx = intToHex(x);
    addHexStringInVector(byteArray, xx);
    ofstream filew("sets/trxbl" , ios::binary | ios::out);
    if (!filew) { return "error de escritura"; }
    
    for (unsigned int i = 0; i < byteArray.size(); i++){
        filew.seekp(i);
        filew.put(byteArray[i]);
    }
    filew.close();

    return true;

}

int maxclientresp(){
    vector<uint8_t> v = readFile("sets/maxclientresp");
    string blockread = "";
    for (unsigned int i = 0; i < v.size(); i++){
        blockread += byteToHex(v[i]);
    }

    return hexToInt(blockread);
}

bool setmaxclientresp(int x){

    vector<unsigned char> byteArray;
    string xx = intToHex(x);
    addHexStringInVector(byteArray, xx);
    ofstream filew("sets/maxclientresp" , ios::binary | ios::out);
    if (!filew) { return "error de escritura"; }
    
    for (unsigned int i = 0; i < byteArray.size(); i++){
        filew.seekp(i);
        filew.put(byteArray[i]);
    }
    filew.close();

    return true;

}

int portset(){
    vector<uint8_t> v = readFile("sets/port");
    string blockread = "";
    for (unsigned int i = 0; i < v.size(); i++){
        blockread += byteToHex(v[i]);
    }
    extern string F256;
    if (blockread == F256){
        return 18090;
    }

    return hexToInt(blockread);
}

bool portsetting(int x){

    vector<unsigned char> byteArray;
    string xx = intToHex(x);
    addHexStringInVector(byteArray, xx);
    ofstream filew("sets/port" , ios::binary | ios::out);
    if (!filew) { return "error de escritura"; }
    
    for (unsigned int i = 0; i < byteArray.size(); i++){
        filew.seekp(i);
        filew.put(byteArray[i]);
    }
    filew.close();

    return true;

}

string feedToDirset(){
    vector<uint8_t> v = readFile("sets/FeedsTo");
    string blockread = "";
    for (unsigned int i = 0; i < v.size(); i++){
        blockread += byteToHex(v[i]);
    }
    extern string F256;
    if (blockread == F256){
        ifstream archivo2("node/priv");
        if (archivo2.is_open()){
            string pr;
            getline(archivo2, pr);
            string publicDirNode = derivate(pr);
            pr="";
            return publicDirNode;
        }
        
    }

    return blockread.substr(0,130);
}

bool feedToDirsetting(string x){

    vector<unsigned char> byteArray;

      if( x.length() != 128 || !HexCheck(x)){ 
            cout<<endl<<"address setting invalid"<<endl;
            return false ;
    }

    addHexStringInVector(byteArray, x);
    ofstream filew("sets/FeedsTo" , ios::binary | ios::out);
    if (!filew) { return "error de escritura"; }
    
    for (unsigned int i = 0; i < byteArray.size(); i++){
        filew.seekp(i);
        filew.put(byteArray[i]);
    }
    filew.close();

    return true;

}

uint feedRatioset(){
    vector<uint8_t> v = readFile("sets/FeedsRatio");
    string blockread = "";
    for (unsigned int i = 0; i < v.size(); i++){
        blockread += byteToHex(v[i]);
    }
    extern string F256;
    if (blockread == F256){

            return 300;
        }

    return hexToInt(blockread.substr(0,8));
}

bool feedRatiosetting(uint x){

    vector<unsigned char> byteArray;

      if( x > 4000 ){ 
            cout<<endl<<"feed ratio setting value is wrong"<<endl;
            return false ;
    }

    addHexStringInVector(byteArray, intToHex(x));
    ofstream filew("sets/FeedsRatio" , ios::binary | ios::out);
    if (!filew) { return "error de escritura"; }
    
    for (unsigned int i = 0; i < byteArray.size(); i++){
        filew.seekp(i);
        filew.put(byteArray[i]);
    }
    filew.close();

    return true;

}

uint shablbmaxbufferset(){
    vector<uint8_t> v = readFile("sets/shablbmaxbuffer");
    string blockread = "";
    for (unsigned int i = 0; i < v.size(); i++){
        blockread += byteToHex(v[i]);
    }
    extern string F256;
    if (blockread == F256){

            return 8000000;
        }

    return hexToInt(blockread.substr(0,8));
}

bool shablbmaxbuffersetting(uint x){

    vector<unsigned char> byteArray;


    addHexStringInVector(byteArray, intToHex(x));
    ofstream filew("sets/shablbmaxbuffer" , ios::binary | ios::out);
    if (!filew) { return "error de escritura"; }
    
    for (unsigned int i = 0; i < byteArray.size(); i++){
        filew.seekp(i);
        filew.put(byteArray[i]);
    }
    filew.close();

    return true;

}

uint accIndexMaxCacheset(){
    vector<uint8_t> v = readFile("sets/accIndexMaxCache");
    string blockread = "";
    for (unsigned int i = 0; i < v.size(); i++){
        blockread += byteToHex(v[i]);
    }
    extern string F256;
    if (blockread == F256){

            return 4096;
        }

    return hexToInt(blockread.substr(0,8));
}

bool accIndexMaxCachesetting(uint x){

    vector<unsigned char> byteArray;


    addHexStringInVector(byteArray, intToHex(x));
    ofstream filew("sets/accIndexMaxCache" , ios::binary | ios::out);
    if (!filew) { return "error de escritura"; }
    
    for (unsigned int i = 0; i < byteArray.size(); i++){
        filew.seekp(i);
        filew.put(byteArray[i]);
    }
    filew.close();

    return true;

}

uint64_t GetTimingBlSetting(){
    vector<uint8_t> v = readFile("sets/TimingBl");
    string blockread = "";
    for (unsigned int i = 0; i < v.size(); i++){
        blockread += byteToHex(v[i]);
    }
    extern string F256;
    if (blockread == F256){
            return 600;
    }


    return hexToUint64(blockread.substr(0,16));
}

bool SetTimingBl(uint64_t x){

    if(x>1800){
        cout <<"set timing per block admin setting > 1800";
        return false;
    }

    vector<unsigned char> byteArray;
    addHexStringInVector(byteArray, uint64ToHex(x));
    ofstream filew("sets/TimingBl" , ios::binary | ios::out);
    if (!filew) { return "error de escritura"; }
    
    for (unsigned int i = 0; i < byteArray.size(); i++){
        filew.seekp(i);
        filew.put(byteArray[i]);
    }
    filew.close();

    return true;

}



#endif

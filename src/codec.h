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

#ifndef CODEC_H
#define CODEC_H

#include <iostream>
#include <sstream>

using namespace std;

uint8_t hexToUint8_t(const std::string hex) {
    if (hex.length() != 2) {
        std::cerr << "Error: the hex-string provided length != 2 " <<hex.length()<<endl;
        return 0;
    }

    std::istringstream iss(hex);
    uint16_t result;
    iss >> std::hex >> result;

    if (iss.fail()) {
        std::cerr << "Error: the hex-string provided length != 2" << std::endl;
        return 0;
    }

    return result;
}


string ullToHex(unsigned long long ullValue){
    stringstream ss;
    ss << hex << uppercase << setw(16) << setfill('0') << ullValue;
    return ss.str();
}

string uint64ToHex(uint64_t Value){
    stringstream ss;
    ss << hex << uppercase << setw(16) << setfill('0') << Value;
    return ss.str();
}

string intToHex(uint Value){
    stringstream ss;
    ss << hex << uppercase << setw(8) << setfill('0') << Value;
    return ss.str();
}

string uintToHex(uint Value){
    stringstream ss;
    ss << hex << uppercase << setw(8) << setfill('0') << Value;
    return ss.str();
}

string uint32ToHex(uint32_t Value){
    stringstream ss;
    ss << hex << uppercase << setw(8) << setfill('0') << Value;
    return ss.str();
}

string uint16ToHex(uint16_t Value){
    stringstream ss;
    ss << hex << uppercase << setw(4) << setfill('0') << Value;
    return ss.str();
}

string uint8ToHexPatch(uint16_t Value){
    stringstream ss;
    ss << hex << uppercase << setw(4) << setfill('0') << Value;
    return ss.str().substr(2,2);
}
 
string uint8ToHex(uint8_t Value){
    cout<<endl<<"call to uint8ToHex, is bugged!!!";
    stringstream ss;
    ss << hex << uppercase << setw(2) << setfill('0') << Value;
    return ss.str();
}

string intTobytecharhex(uint Value){
    stringstream ss;
    ss << hex << uppercase << setw(4) << setfill('0') << Value;
    return ss.str();
}

string unsignedCharToHex(uint Value){
    stringstream ss;
    ss << hex << uppercase << setw(2) << setfill('0') << Value;
    return ss.str();
}

bool isHexDigit(char c){
    return ((c >= '0' && c <= '9') ||(c >= 'A' && c <= 'F')||(c >= 'a' && c <= 'f'));
}

string bytesToHexStr(const vector<uint8_t>& bytes){
    stringstream ss;
    ss << hex << setw(2) << setfill('0') ;
    for(const auto& byte : bytes) {
        ss<<setw(2)<<static_cast<uint8_t>(byte);
    }
    string str= ss.str();
    for (auto &c : str){c = toupper(c);}
    return str;
}

vector<uint8_t> HexStrToBytes(const std::string& str){
    vector<uint8_t>Data;
    for(uint i = 0; i<str.length();i+=2){
        Data.push_back(hexToUint8_t(str.substr(i,2)));
    }
    return Data;
}

string byteToHex(unsigned char byteValue){
    stringstream ss;
    ss << hex << setw(2) << setfill('0') << (int)byteValue;
    return ss.str();
}

string byteToHex2(unsigned char &byteValue){
    stringstream ss;
    ss << hex << setw(2) << setfill('0') << (int)byteValue;
    string str= ss.str();
    for (auto &c : str){c = toupper(c);}
    return str;
}

string byteVectorToHexStr(const vector<unsigned char>& bytes){

    string str="";

    for(uint i =0; i<bytes.size();i++){
        str+=byteToHex(bytes[i]);
    }

    return str;
}

string constByteToHex2(const unsigned char &byteValue){
    stringstream ss;
    ss << hex << setw(2) << setfill('0') << (int)byteValue;
    string str= ss.str();
    for (auto &c : str){c = toupper(c);}
    return str;
}

uint64_t hexToULL(string c){
    // Verificar que el string solo contenga caracteres hexadecimales
    for (unsigned int i = 0; i < c.length(); i++) {
        if (!isHexDigit(c[i])) {
            
            cerr << "El string contiene caracteres no hexadecimales" << endl;
            cout<<endl<<"error "<<c<<endl;
            return 0;
        }
    }
    stringstream ss;
    ss << hex << c;
    uint64_t ullValue;
    ss >> ullValue;
    return ullValue;
}

uint64_t hexToUint64(string c){
    // Verificar que el string solo contenga caracteres hexadecimales
    for (unsigned int i = 0; i < c.length(); i++) {
        if (!isHexDigit(c[i])) {
            
            cerr << "El string contiene caracteres no hexadecimales" << endl;
            cout<<endl<<"error "<<c<<endl;
            return 0;
        }
    }
    stringstream ss;
    ss << hex << c;
    uint64_t ullValue;
    ss >> ullValue;
    return ullValue;
}

unsigned char hexToUnsignedChar(string c){

    for (unsigned int i = 0; i < c.length(); i++) {
        if (!isHexDigit(c[i])) {
            cerr << "El string contiene caracteres no hexadecimales" << endl;
            return 1;
        }
    }
    stringstream ss;
    ss << hex << c;
    unsigned char intValue;
    ss >> intValue;
    return intValue;

}

int hexToInt(std::string c){
    // Verificar que el string solo contenga caracteres hexadecimales
    for (unsigned int i = 0; i < c.length(); i++) {
        if (!isHexDigit(c[i])) {
            cerr << "the string have non-hex chars" << endl;
            return 1;
        }
    }
    stringstream ss;
    ss << hex << c;
    int intValue;
    ss >> intValue;
    return intValue;
}

uint hexToUint(std::string c){
    for (unsigned int i = 0; i < c.length(); i++) {
        if (!isHexDigit(c[i])) {
            cerr << "the string have non-hex chars" << endl;
            return 1;
        }
    }
    stringstream ss;
    ss << hex << c;
    uint intValue;
    ss >> intValue;
    return intValue;
}

uint hexToUint32(std::string c){
    for (unsigned int i = 0; i < c.length(); i++) {
        if (!isHexDigit(c[i])) {
            cerr << "El string contiene caracteres no hexadecimales" << endl;
            return 1;
        }
    }
    stringstream ss;
    ss << hex << c;
    uint32_t intValue;
    ss >> intValue;
    return intValue;
}

uint hexToUint16(std::string c){
    for (unsigned int i = 0; i < c.length(); i++) {
        if (!isHexDigit(c[i])) {
            cerr << "El string contiene caracteres no hexadecimales" << endl;
            return 1;
        }
    }
    stringstream ss;
    ss << hex << c;
    uint16_t intValue;
    ss >> intValue;
    return intValue;
}


bool HexCheck(std::string c){
    for (unsigned int i = 0; i < c.length(); i++) {
        if (!isHexDigit(c[i])) {
            cerr << "Error encoding or DB issue" << endl;
            return false;
        }
    }
    return true;
}

/*
std::string byteToHex(uint8_t byteValue) {
    std::stringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint16_t>(byteValue);
    return ss.str();
}
*/


#endif

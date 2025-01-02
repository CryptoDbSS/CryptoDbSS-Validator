/*
 * Software Name: CryptoDbSS
 * Copyright (C) 2024 Steeven J Salazar.
 * License: CryptoDbSS: Software Review and Audit License
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

questions, suggestions or contact : Steevenjavier@gmail.com


Third-party dependencies: CrowCpp, Crypto++, OpenSSL, Boost, ASIO, libcurl.

Build on GNU/Linux Debian with: g++ CryptoDbSS.cpp -o ../bin/CryptoDbSS -lpthread -DCROW_ENABLE_SSL -lssl -lcrypto -lcryptopp -DCURL_STATICLIB -lcurl -std=c++17


*/

#ifndef FUNCIONES_H
#define FUNCIONES_H


#include "CryptoDbSS.cpp"

using namespace std;

string readTransacFirmString(string &stg);
bool blread2(const std::string& filename,vector<unsigned char> &bl2);
string blread(string bl);


extern uint64_t lastbl;


void blockThread(bool &threadbool , string threadName, uint sleepfor){

    while(threadbool){cout<<endl<<threadName;
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepfor));
    }
    while(threadbool){cout<<endl<<threadName;
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepfor));
    }
    threadbool = true;

}
 
void exit_call(){
    cout<<"Error Exit";
    exit(0);
}

string LocalSigner(string data){
    ifstream archivo2("node/priv");
    string signature = "";
    if (archivo2.is_open()){
        string pr;
        getline(archivo2, pr);
        signature = Signer( pr, data);
        pr="";
    }
    archivo2.close();
    return signature;
}

vector<uint8_t> stringToBytes(const string& str) {
    return vector<uint8_t>(str.begin(), str.end());
}

string bytesToString(const vector<uint8_t>& bytes) {
    return string(bytes.begin(), bytes.end());
}

string bytesIndexToString(const vector<uint8_t>& bytes, uint from, uint to) {
    return string(bytes[from], bytes[to]);
}

void addHexStringInVector(vector<unsigned char> &vec, string datatocodify){
    uint datatocodifylength =datatocodify.length();
    for (uint i = 0; i < datatocodifylength; i += 2){
        vec.push_back(hexToInt(datatocodify.substr(i, 2)));
    }
    return;
}

vector<uint8_t> readFile(const std::string& filename) {
    
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
try {

    if (!file.is_open()) {
        // Manejo de error si no se pudo abrir el archivo
        throw std::runtime_error("No se pudo abrir el archivo");
                
    }

    }
    catch (const std::exception& e) {
        file.close();
        std::cerr << "Error: " << e.what() << std::endl;
        extern string F256;
        vector<uint8_t> vecff;
        addHexStringInVector(vecff, F256);
        return vecff;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);

    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        file.close();
        // Manejo de error si no se pudo leer el archivo
         throw std::runtime_error("No se pudo leer el archivo");

    }

    file.close();
    return buffer;

}



bool compareArrayToVector(const vector<unsigned char>& vec, size_t vecStart, array<unsigned char, 64 > acc, size_t arrSize) {

    for (size_t i = 0; i < arrSize; i++) {
        if (acc[i] != vec[vecStart + i]) {
            return false;
        }
    }
    return true;
}


uint32_t readUint32FromBl(const std::vector<unsigned char>& vec, size_t startIndex) {

    if (startIndex + 3 >= vec.size()) {
        return 0; 
    }
    uint32_t result = 0;
    for (size_t i = 0; i < 4; ++i) {
        result = (result << 8) | static_cast<uint32_t>(vec[startIndex + i]);
    }

    return result;
}

uint64_t readUnsignedLongLongFromBl(const vector<unsigned char>& vec, size_t startIndex) {

    if (startIndex + 7 >= vec.size()) {
        return 0; 
    }
    uint64_t result = 0;
    for (size_t i = 0; i < 8; ++i) {
        result = (result << 8) | static_cast<uint64_t>(vec[startIndex + i]);
    }

    return result;
}

uint64_t readbalanceFromDatatransacArray(unsigned char (&DataTransac)[247],bool side){
    uint64_t result = 0;
    if (side){
        result = 0;
        size_t startIndex = 137;
        for (size_t i = 0; i < 8; ++i) {
            result = (result << 8) | static_cast<uint64_t>(DataTransac[startIndex + i]);
        }
    }else {
        result = 0;
        size_t startIndex = 65;
        for (size_t i = 0; i < 8; ++i) {
            result = (result << 8) | static_cast<uint64_t>(DataTransac[startIndex + i]);
        }
    }
    return result;
}

array<unsigned char, 64> ArrayAccBuffer(const vector<unsigned char>& vec, size_t startIndex) {
    array<unsigned char, 64> result = {};

    // Verificar que el índice de inicio esté dentro de los límites del vector
    if (startIndex >= vec.size()) {
        return result;
    }

    // Copiar los elementos del vector a la array, a partir del índice de inicio
    for (size_t i = 0; i < 64; ++i) {
        size_t index = startIndex + i;
        if (index < vec.size()) {
            result[i] = vec[index];
            cout<< byteToHex(result[i]);
        }
    }

    return result;
}

uint WriteSpaceOp (vector <unsigned char>byteArray){
    extern uint wirtespacecount;
    return wirtespacecount++;
}

string timing(){
    time_t LocalTime = time(nullptr);
    string localtimestg = to_string(LocalTime);
    return localtimestg;
}

string vectorstring(vector<unsigned char> &vec){
    string msg = "";
    for (unsigned int i = 0; i < vec.size(); i++){
        msg += byteToHex2(vec[i]);
    }
    return msg;
}

bool FIRMCheck2(string sth, string blheaderdata){

/*
    cout<<endl<<"bloque: "<<sth;
    cout<<endl<<"datatransacString: "<<dataTransacString(sth);
    cout<<endl<<"hidden data: "<<blheaderdata<<endl;
    cout<<endl<<"readfirm: "<<readTransacFirmString(sth);
    cout<<endl<<"publickey: "<< readaccountString(sth,false) <<endl;

    cout<< " firmcheck2 data transac "<<sth+blheaderdata<<endl<<endl;
    cout<< " firmcheck2 data readTransacFirmString(sth) "<<readTransacFirmString(sth)<<endl<<endl;
    cout<< " firmcheck2 publicsigner "<<readaccountString(sth,false)<<endl<<endl;
*/

    if(!verifySignature(sth.substr(0,302)+blheaderdata, readTransacFirmString(sth), loadPublicKey(readaccountString(sth,false)))){
        return false;
    }
    
    return true;
}

string shablArrToString(array<unsigned char, 32> &shablbbuffer ){
    string sharead="";
    vector <unsigned char>shavecread;
    for (uint8_t i = 0 ; i<32 ; i++){
        shavecread.push_back(shablbbuffer[i]);
    }
    return vectorstring(shavecread);
}

string ShaBlB2(uint64_t queryShaBl){

    extern uint shablbmaxbuffer;
    extern map<uint64_t, array<unsigned char, 32>> shablbbuffer2;

    if( shablbbuffer2.size()>=shablbmaxbuffer){

        auto lastElement = shablbbuffer2.rbegin();
        if (lastElement != shablbbuffer2.rend()) {
            shablbbuffer2.erase(lastElement->first);
        }
    }

    auto iterador = shablbbuffer2.find(queryShaBl);
    if(iterador != shablbbuffer2.end()) {

        return shablArrToString(shablbbuffer2[queryShaBl]);
    } else {
        vector<unsigned char> bl2;

        if(blread2(to_string(queryShaBl),bl2)){ 

            vector<unsigned char> blhashed = sha3_256v(bl2);

            for (uint8_t i = 0; i<32;  i++){
                shablbbuffer2[queryShaBl][i]=blhashed[i];
            }
            return shablArrToString(shablbbuffer2[queryShaBl]);
        } else {
            cout<<endl<<"debug ShaBlB2 !blread2"<<endl;
        }
    }

  return "error ShaBlB2";
}

string shaLBB(){

    extern mutex shaLBBmtx;
    extern string ShaLBBBuffered;
    std::unique_lock<std::mutex> shaLBBmtxlock(shaLBBmtx);

    string lbb = ullToHex(lastbl); 
    if(ShaLBBBuffered.length()== 80){
        string shabuffer =  ShaLBBBuffered.substr(0,64);
        if(ShaLBBBuffered.substr(64,16)==lbb){
            return shabuffer;
        }
    }

    vector<unsigned char> vec;
    blread2(to_string(lastbl),vec);
    vector<uint8_t> hashed = sha3_256v(vec);
    string data66 =  vectorstring(hashed);
    for (auto &c:data66){c=toupper(c);}
    ShaLBBBuffered = data66+ lbb;
    return data66;
}

vector<unsigned char> writeULongToVector(vector<unsigned char>& vec, size_t index, unsigned long long value) {

    if (index + 8 > vec.size()) {
        throw out_of_range("Index out of range");
    }
    for (size_t i = 0; i < 8; i++) {
        vec[index + i] = static_cast<unsigned char>(value & 0xFF);
        value >>= 8;
    }
    return vec;
}

bool compareULongToCharVector(unsigned long long ulongVal, const vector<unsigned char>& ShaLBBBufferedVec, size_t startIndex) {
    size_t length = 32;
    if (length > sizeof(unsigned long long)||ShaLBBBufferedVec.size()!=40) {
        return false;
    }
    unsigned long long temp = ulongVal;
    for (size_t i = 0; i < length; i++) {
        if ((temp & 0xFF) != ShaLBBBufferedVec[startIndex + i]) {
            return false;
        }
        temp >>= 8;
    }
    return true;
}

void shaLBBArr(){

    extern vector<unsigned char> ShaLBBBufferedArr;
    unsigned long long lbb = lastbl; 

    if(compareULongToCharVector(lbb, ShaLBBBufferedArr, 32 )){
        return ;
    };[[]]

    vector<uint8_t> hashed = sha3_256v(ShaLBBBufferedArr);

    for(int i = 0; i<32; i++){
        ShaLBBBufferedArr[i] =  hashed[i];
    }
    writeULongToVector(ShaLBBBufferedArr,32,lbb );

    return ;
}

bool compareULongToCharArray(unsigned long long ulongVal, array<unsigned char, 40> ShaLBBBufferedArr, size_t startIndex) {

    size_t length = 16;

    if (length > sizeof(unsigned long long)) {
        return false;
    }

    // Crear una copia temporal del unsigned long long
    unsigned long long temp = ulongVal;

    // Recorrer la sección del array y compararla con el unsigned long long
    for (size_t i = 0; i < length; i++) {
        if ((temp & 0xFF) != ShaLBBBufferedArr[startIndex + i]) {
            return false;
        }
        temp >>= 8;
    }

    return true;
}

string SHAstg(string stg){

    for (auto &c:stg){c=toupper(c);}
    vector<uint8_t> hashed = sha3_256(stg);
    string data66 =  vectorstring(hashed);
    for (auto &c:data66){c=toupper(c);}
    return data66;
    
}

string SHAvector(vector<uint8_t> stg){
    vector<uint8_t> hashed = sha3_256v(stg);
    string data66 =  vectorstring(hashed);
    for (auto &c:data66){c=toupper(c);}
    return data66;
}

bool comp(int blockcheck) {
    
        ifstream HashR("blocks/" + to_string(blockcheck), ios::binary | ios::in);
        char readCharHash;
        string HasHeadRead= "";
        vector<uint8_t>hashed = sha3_256(blread(to_string(blockcheck-1)));
        for (unsigned int i = 0; i <= 31; i++ ){
            HashR.seekg(i);
            HashR.get(readCharHash); // Leer el carácter en la posición actual
            HasHeadRead += byteToHex(readCharHash);
        }
        HashR.close();
        if ( vectorstring(hashed)== HasHeadRead ){return true;}
        if (blockcheck < 2){return true;}

        return false;

}

void addStringInVector(vector<string> &vec, string datatocodify){
    for (unsigned int i = 0; i < datatocodify.length(); i += 2){
        vec.push_back(datatocodify.substr(i, 2));
    }
}

string printdebug(string msg){
    cout<<endl<<msg<<endl;
    return msg;
}

array<unsigned char, 64 > accArr(string acctpubk) {

    array<unsigned char, 64 > acca ;

    for (int i = 0, e = 0; i < 128; i += 2) {
        acca[e++] = hexToUint8_t(acctpubk.substr(i, 2));
    }

    return acca;
}


#endif

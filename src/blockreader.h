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

#ifndef BLOCKREADER_H
#define BLOCKREADER_H

#include "CryptoDbSS.cpp"

using namespace std;

bool HexCheck(std::string c);
bool checkSumsBalances(vector<unsigned char>bl2,array<unsigned char, 64> accA, unsigned char (&DataTransac)[247],string &AccBStr, uint &primer, uint64_t last, uint16_t &index,bool AccBside);


extern uint64_t lastbl;
extern map<uint16_t,bool> numberspace;
extern vector<string> MatchminTransacs;

////////////////////////////////////////////////////////////////
//    bl head

vector<uint8_t> blread1(string bl){
    extern bool lastblockbuildBlock;
    while (lastblockbuildBlock ){cout<<endl<<"lastblockbuild";
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    lastblockbuildBlock=true;

    if(HexCheck(bl)){

        const std::string path = "blocks/";
        for (const auto &entry : std::filesystem::directory_iterator(path)) {
            if(entry.path().filename().string()==bl){ 
                if (entry.is_regular_file()) {
                    std::ifstream file("blocks/"+bl, std::ios::binary | std::ios::ate);
                    if (!file.is_open()) {
                    // Manejo de error si no se pudo abrir el archivo
                     lastblockbuildBlock=false;
                        throw std::runtime_error("No se pudo abrir el archivo");
                    }

                    std::streamsize size = file.tellg();
                    file.seekg(0, std::ios::beg);
                    std::vector<uint8_t> buffer(size);
    
                    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
                        // Manejo de error si no se pudo leer el archivo
                        file.close();
                        lastblockbuildBlock=false;
                        throw std::runtime_error("No se pudo leer el archivo");
                    }
                    file.close();
                    lastblockbuildBlock=false;
                    return buffer;
                }
            }
        }
    }
vector<uint8_t> a;
lastblockbuildBlock=false;
return a;

}

bool blread2(const std::string& filename,vector<unsigned char> &bl2) {
    
    std::ifstream file("blocks/"+filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        cout<<endl<<"error blread2 !file.is_open()"<<endl;
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<unsigned char> ReadBuffer(size);
    
    if (!file.read(reinterpret_cast<char*>(ReadBuffer.data()), size)) {
        cout<<endl<<"error blread2 !file.read(reinterpret_cast<char*>(ReadBuffer.data()), size)"<<endl;
        exit_call();
        return false;
    }

    bl2.clear();
    bl2 = ReadBuffer;

    file.close();

    if (bl2.size()<213){
        cout<<endl<<"error blread2  bl2.size()<213"<<endl;
        exit_call();
    } else {
        return true;
    }

    return false;

}

string blkscontain2(vector<unsigned char> &bl2){
    string bl="";
    for(uint8_t i = 177; i < 179;i++){
        bl += byteToHex (bl2[i]);
    }
    return bl;
}

string idpublicsigner2(vector<unsigned char> bl2){

    string bl;
    for(int i = 65; i < 32+65;i++){
        bl +=byteToHex2(bl2[i]);
    }
    return bl;
}

void idpublicsignerBuilddataTranasacArray(vector<unsigned char> bl2, array<unsigned char,247> &DataTransac ){

    string bl;
    uint e= 215;
    for(int i = 65; i < 97;i++,e++){
        DataTransac[e] =bl2[i];
    }
    return ;
}

array<unsigned char, 64 > readAddressFeedBl(vector<unsigned char> bl2){
    array<unsigned char, 64 > acca ;
    for(uint16_t i = 97, e = 0 ; i <161; i++){
    acca[e++] = bl2[i];
    }
    return acca;
}

bool build_blks(uint &qttblks, uint64_t &last, vector<unsigned char> &bl2 ){

    blread2(to_string(last),bl2);
    qttblks = hexToULL(blkscontain2(bl2));
    uint primerInit=179;
    uint blsize  = bl2.size();

    for(uint i = 0 ; i<qttblks; i++){

        if(primerInit>blsize ){
            cout<<endl<<"error reading block transac 1 "<<blsize<<endl;
            exit_call();
        }

        PrimerChange(bl2[primerInit],primerInit );

    }
    for (uint i = primerInit; i<primerInit+2;i++){
        if (byteToHex2( bl2[i]) != "96"){
            cout<<endl<<"error reading block transac 3 "<< byteToHex2( bl2[i])<<endl;
            exit_call();
            return false;
        }

    }

    return true;

}

uint64_t readAddressFeedBlBalance (vector<unsigned char> bl2){

    cout<<endl<< "debug readAddressFeedBlBalance ";
    uint8_t arrvar[8];

    /*
    for(uint16_t i = 162, e = 0 ; i <170; i++){
        arrvar[e++] = bl2[i];
        cout<<byteToHex2(bl2[i]);
    }
    cout<<endl;
    */

    for(uint16_t i = 161, e = 0 ; i <169; i++){
        arrvar[e++] = bl2[i];
        cout<<byteToHex2(bl2[i]);
    }
    cout<<endl;
    uint64_t uintvar = (static_cast<uint64_t>(arrvar[0]) << 56) |
                   (static_cast<uint64_t>(arrvar[1]) << 48) |
                   (static_cast<uint64_t>(arrvar[2]) << 40) |
                   (static_cast<uint64_t>(arrvar[3]) << 32) |
                   (static_cast<uint64_t>(arrvar[4]) << 24) |
                   (static_cast<uint64_t>(arrvar[5]) << 16) |
                   (static_cast<uint64_t>(arrvar[6]) << 8) |
                   (static_cast<uint64_t>(arrvar[7]));

    return uintvar;
}

int  signersqty2(vector<unsigned char> bl2){

    string primerBase = "0000";
    int signersSum=0;
    int primerPosition = 187; 

    string bl="";


    int ender = primerPosition+2;

    for(int i = primerPosition; i < ender;i++){
        bl+=byteToHex(bl2[i]);
    }

   // cout<<" bl == 0000 :"<< bl <<" == 0000"<<endl;
    //cout<<endl<<"primerPosition "<< primerPosition;

    primerPosition+=34;
    //cout<<endl<<"primerPosition "<< primerPosition;
    ender = primerPosition+2;

    while(primerBase == bl){

        //cout<<endl<<"debug signer qtty loop"<<endl;
        
        bl="";
        signersSum++;
        
        for(primerPosition; primerPosition < ender;primerPosition++){
           // cout<<bl2[primerPosition];
            bl += byteToHex(bl2[primerPosition]);
        }

        primerPosition +=32;
        ender=+primerPosition+2;
    }

    //cout<<endl<<" bl debug " << bl<<endl;

    //cuando no es 0101 crashea manejar error
    if(bl != "0101"){
        cout<<"error signersqty2 !0101";
        return 0;}

    return signersSum;
}

string blhead2(vector<unsigned char> bl2){
    string bl="";
    for(int i = 0; i < 32;i++){
        bl +=byteToHex2(bl2[i]);
    }
    return bl;
}

string blread(string bl){
    if(HexCheck(bl)){
        const std::string path = "blocks/";
        for (const auto &entry : std::filesystem::directory_iterator(path)) {
            if(entry.path().filename().string()==bl){ 
                if (entry.is_regular_file()) {
                    ifstream QueryDBB(path + bl, ios::binary | ios::in);
                
                    QueryDBB.seekg(0, std::ios::end);
                    streampos tamano = QueryDBB.tellg();
                    int tamanoentero=static_cast<int>(tamano);
                    char readChar;
                    string blockread = "";
                    if (!QueryDBB) { return "no se cargo el archivo ";}

                    for (unsigned int i = 0; i < tamanoentero; i++){
                        QueryDBB.seekg(i);
                        QueryDBB.get(readChar); // Leer el carácter en la posición actual
                        blockread += byteToHex(readChar);
                    }
                    QueryDBB.close();
                    for (auto &s : blockread){s = toupper(s);}
                    return blockread;
                }
            }
        }
    }

return "Bad_Query_DB";
}

string blreadblocksearch(const std::string& filename ) {

    if(HexCheck(filename)){
        const std::string path = "blocks/";
        for (const auto &entry : std::filesystem::directory_iterator(path)) {
            if(entry.path().filename().string()==filename){ 
                if (entry.is_regular_file()) {

                    std::ifstream file("blocks/"+filename, std::ios::binary | std::ios::ate);
                    if (!file.is_open()) {
                        // Manejo de error si no se pudo abrir el archivo
                        throw std::runtime_error("No se pudo abrir el archivo");
                    }

                    std::streamsize size = file.tellg();
                    file.seekg(0, std::ios::beg);
                    std::vector<unsigned char> buffer(size);

                    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
                        // Manejo de error si no se pudo leer el archivo
                        throw std::runtime_error("No se pudo leer el archivo");
                    }

                    file.close();
                    string blstr="";
                    for(uint i = 0; i<buffer.size();i++){
                        blstr+=byteToHex2(buffer[i]);

                    }
                    return blstr;
                }
            }
        }
    }
    return "Ops Wrong block Request";
    
}

string blreadblock(const std::string& filename ) {

    if(HexCheck(filename)){
 

                    std::ifstream file("blocks/"+filename, std::ios::binary | std::ios::ate);
                    if (!file.is_open()) {
                        // Manejo de error si no se pudo abrir el archivo
                        throw std::runtime_error("No se pudo abrir el archivo");
                    }

                    std::streamsize size = file.tellg();
                    file.seekg(0, std::ios::beg);
                    std::vector<unsigned char> buffer(size);

                    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
                    // Manejo de error si no se pudo leer el archivo
                    throw std::runtime_error("No se pudo leer el archivo");
                    }

                    file.close();
                    return bytesToHexStr(buffer);
                
            
        }
    
    return "Ops Wrong block Request";
    
}

unsigned long long lastblockbuild(){

    extern bool lastblockbuildBlock;

    lastblockbuildBlock=true;

    filesystem::path directory = "blocks/";
    vector<string> fileNames;// Vector para almacenar los nombres de los archivos

    vector<unsigned long long> fileNumbers;// Vector para almacenar los valores numéricos en los nombres de los archivos

    for (const auto &file : filesystem::directory_iterator(directory))// Iterar a través de los archivos en el directorio
    {
        string fileName = file.path().filename().string();  // Obtener el nombre del archivo
        fileNames.push_back(fileName);// Agregar el nombre del archivo al vector de nombres de archivo        
        size_t numberPos = fileName.find_first_of("0123456789");// Buscar la posición del número en el nombre del archivo

        if (numberPos != string::npos) // Comprobar que se encontró un número antes de obtener la subcadena
        {
            string numberString = fileName.substr(numberPos); // Obtener la porción del nombre del archivo que contiene el número            
            unsigned long long number = stoi(numberString);// Convertir el número a un entero y agregarlo al vector de números de archivo
            fileNumbers.push_back(number);
        }
        else {
            fileNumbers.push_back(0);// Si no se encuentra un número, agregar un valor predeterminado al vector de números de archivo
        }
    }

    // Encontrar el archivo con el número más grande
    auto maxElement = max_element(fileNumbers.begin(), fileNumbers.end());
    unsigned long long maxIndex = distance(fileNumbers.begin(), maxElement);
    string maxFileName = fileNames[maxIndex];

    // Imprimir el nombre del archivo con el número más grande
    try{
     stoi(maxFileName);
    } catch (const std::exception& e) {
        lastblockbuildBlock=false;
        return 0;
    }
    lastblockbuildBlock=false;
    return stoi(maxFileName);
}

string blhead(string bl){
    return bl.substr(0, 64);
}

string typebl(string bl){
    return bl.substr(0, 2);
}

uint8_t typebl2(string bl){
    return hexToUint8_t(bl.substr(0, 2));
}

string idblockchain(string bl){
    return bl.substr(68, 64);
}

string idpublicsigner(string bl){
    return bl.substr(132, 64);
}

string AddrssBl(string bl){
    return bl.substr(322, 128);
}

string valueAddrssBl(string bl){
    return bl.substr(326, 16);
}

string Feeds(string bl){
    return bl.substr(342, 8);
}

string blnmb(string bl){
    return bl.substr(350, 16);
}

string blkscontain(string bl){
    return bl.substr(366, 8);
}

int  signersqty(string bl){
    string primerBase = "0000";
    int signersSum=0;
    int primerPosition = 374; 

    while("0000" == bl.substr(primerPosition,4)){
        signersSum++;
        primerPosition =primerPosition+68;
        primerBase = bl.substr(primerPosition,4);
    }
    //cuando no es 0101 crashea manejar error
    if(primerBase != "0101"){return 0;}
    return signersSum;
}

bool saveNewBlock(vector<uint8_t>blData){

    ofstream filew("blocks/" + to_string(lastbl + 1), ios::binary | ios::out);
    if (!filew) {
        return false;
    }

    for (unsigned int i = 0; i < blData.size(); i++){
        filew.seekp(i);
        filew.put(blData[i]);
    }
    filew.close();
    lastbl++;
    return true;
}

//    bl transac
//////////////////////////////////////////////////////////////

bool accsvectorbuilder(vector<unsigned char>& bl2,uint64_t &last, uint &primer,vector<string> &accA,vector<string> &accB){

    accA.clear();
    accB.clear();

    cout<<endl<<" debug accsvectorbuilder() ";

    uint8_t blType = getBlCompressType(bl2[primer]);

    cout<<endl<<" debug accsvectorbuilder() blType" <<to_string(blType)<<endl;

    if(blType==0x00||blType==0x04||blType==0x06||blType==0x08||blType==0x0E){

        //Check if Acc indexing is on accRPoint
        string accBStr="";
        for(int i = 0; i<64; i++){
            accBStr+= byteToHex(bl2[primer +1+i]);
        }
        accA.push_back(accBStr);

        accBStr="";
        for(int i = 0; i<64; i++){
            accBStr+= byteToHex(bl2[primer +73+i]);
        }
        accB.push_back(accBStr);

        return true;
    }

    if(blType==0x0B||blType==0x11){
 
        uint8_t compressedPoint[4];
        getCompressedPointBlTransac(bl2,compressedPoint,primer,false);

        //Check if Acc indexing is on accRPoint
        //build accL accounts in vector to firm verifier

        buildAccbVector(accA ,last,compressedPoint);
        string accBStr="";
        for(int i = 0; i<64; i++){
            accBStr+= byteToHex2(bl2[primer +13+i]);
        }
        accB.push_back(accBStr);
        return true;

    }

    if(blType==0x0C||blType==0x14||blType==0x13||blType==0x15){

        string accBStr="";
        for(int i = 1; i<65; i++){
            accBStr+= byteToHex2(bl2[primer+i]);
        }
        accA.push_back(accBStr);
 
        uint8_t compressedPoint[4];
        getCompressedPointBlTransac(bl2,compressedPoint,primer,true);

        buildAccbVector(accB ,last,compressedPoint);

        return true;

    }

    if(blType==0x0D||blType==0x0F){

        //Check if Acc indexing is on accLPoint

        string accBStr="";
        for(int i = 0; i<64; i++){
            accBStr+= byteToHex(bl2[primer +1+i]);
        }
        accA.push_back(accBStr);

        accBStr="";
        for(int i = 0; i<64; i++){
            accBStr+= byteToHex(bl2[primer +69+i]);
        }
        accB.push_back(accBStr);

        //Check if Acc indexing is on accRPoint

        return true;
    }

    if(blType==0x10||blType==0x12){
 
        uint8_t compressedPoint[4];
        getCompressedPointBlTransac(bl2,compressedPoint,primer,false);
        buildAccbVector(accA ,last,compressedPoint);
        string accBStr="";
        for(int i = 0; i<64; i++){
            accBStr+= byteToHex(bl2[primer +9+i]);
        }
        accB.push_back(accBStr);

        return true;

    }

    if(blType==0x16||blType==0x18||blType==0x17||blType==0x19){ 

        uint8_t compressedPoint[4];

        cout<<endl<<"debug accvectorbuild f0"<<endl;

        getCompressedPointBlTransac(bl2,compressedPoint,primer,false);
         cout<<endl<<"debug accvectorbuild post getCompressedPointBlTransac ";
        for(int i =  0; i<4; i++){
            cout<< byteToHex2(compressedPoint[i]);
        }
        buildAccbVector(accA ,last,compressedPoint);


        getCompressedPointBlTransac(bl2,compressedPoint,primer,true);
        buildAccbVector(accB ,last,compressedPoint);

        return true;

    }

    cout<<endl<<"error accsvectorbuilder bltype not found "<<endl;
    exit_call();
    return false;

}

bool BuildHiddenData(vector<unsigned char>&bl2, uint64_t &last, unsigned char (&DataTransac)[247]){

    extern vector<unsigned char>IdBlkchain;

    for(uint8_t i =0; i<32;i++){
        DataTransac[i+151]= IdBlkchain[i];
    }
    if(last > 0){
		for(uint8_t i =0; i<32;i++){
            DataTransac[i+183]= bl2[i];
        }
        uint8_t e = 0;
        for(uint8_t i = 65; i < 97;i++,e++){
            DataTransac[e+215]=bl2[i];
        }
		return true;
	}
	if(last == 0){
		for(uint8_t i =0; i<32;i++){
            DataTransac[i+183]= bl2[i];
        }
        uint8_t e = 0;
        for(uint8_t i = 65; i < 97;i++,e++){
            DataTransac[e+215]=bl2[i];
        }
		return true;
	}
    return true;
}

void buildTransacPointerFromBuffer(vector<unsigned char>&bl2, array<unsigned char, 64 > &acc, uint &primer, uint64_t &last, unsigned char (&Transac)[247]){

    extern  vector<unsigned char>IdBlkchain;
    uint8_t BlCompressType = getBlCompressType(bl2[primer]);
 
    if (BlCompressType == 0||BlCompressType == 4||BlCompressType == 6||BlCompressType == 8){
        for(int i =0;i<151;i++){
            Transac[i] = bl2[primer+i];
        }
    }

    //build bltype
    Transac[0]=getBlType(bl2[primer]);
    
    // build AccL

    if (BlCompressType == 0x0B||BlCompressType == 0x10||BlCompressType == 0x11||BlCompressType == 0x12||BlCompressType == 0x16||BlCompressType == 0x17||BlCompressType == 0x18||BlCompressType == 0x19){

        for(int i =1;i<65;i++){
            Transac[i] = acc[i-1];
        }

    } else{ 
        if(BlCompressType == 0x0C||BlCompressType == 0x0D||BlCompressType == 0x0E||BlCompressType == 0x0F||BlCompressType == 0x13||BlCompressType == 0x14||BlCompressType == 0x15){

            for(int i =1;i<65;i++){
                Transac[i] = bl2[primer+i];
            }

        }
    }

    //build valueL Amount

        // accL !valueL
    if (BlCompressType == 0x0B||BlCompressType == 0x11||BlCompressType == 0x16||BlCompressType == 0x18){
        for(uint8_t i =65; i<73 ; i++){
            Transac[i] = bl2[(primer-60)+i];
        }
    }
        // !accL !valueL
    if (BlCompressType == 0x0C||BlCompressType == 0x0E||BlCompressType == 0x14){
        for(uint8_t i =65; i<73 ; i++){
            Transac[i] = bl2[primer+i];
        }
    }
        // !accL valueL
    if (BlCompressType == 0x0D||BlCompressType == 0x0F||BlCompressType == 0x13||BlCompressType == 0x15){
        for(uint8_t i =65; i<69 ; i++){
            Transac[i] = 0;
        }
        for(uint8_t i =69; i<73 ; i++){
            Transac[i] = bl2[(primer-4)+i];
        }
    }
        // accL valueL
    if (BlCompressType == 0x10||BlCompressType == 0x12||BlCompressType == 0x17||BlCompressType == 0x19){
        for(uint8_t i =65; i<69 ; i++){
            Transac[i] = 0;
        }
        for(uint8_t i =69; i<73 ; i++){
            Transac[i] = bl2[(primer-64)+i];
        }
    }

    //build AccR Account

        // accL !valueL !AccR
    if (BlCompressType == 0x0B||BlCompressType == 0x11){
        for(uint8_t i =73, e = primer +13; i<137 ; i++,e++){
            Transac[i] = bl2[(primer-60)+i];
        }
    }
        // !accL !valueL AccR
    if (BlCompressType == 0x0C||BlCompressType == 0x14||BlCompressType == 0x13||BlCompressType == 0x15||BlCompressType == 0x16||BlCompressType == 0x17||BlCompressType == 0x18||BlCompressType == 0x19){
        for(uint8_t i =73; i<137 ; i++){
            Transac[i] = acc[i-73];
        }
    }
        // !accL valueL !AccR
    if (BlCompressType == 0x0D||BlCompressType == 0x0F){
        for(uint8_t i =73; i<137 ; i++){
            Transac[i] = bl2[(primer-4)+i];
        }
    }
        // !accL !valueL !AccR
    if (BlCompressType == 0x0E){
        for(uint8_t i =73; i<137 ; i++){
            Transac[i] = bl2[primer+i];
        }
    }
        // accL valueL !AccR
    if (BlCompressType == 0x10||BlCompressType == 0x12){
        for(uint8_t i =73; i<137 ; i++){
            Transac[i] = bl2[(primer-64)+i];
        }
    }

    //build valueR amount

    if(Transac[0] != 0x04){

            // accL !valueL !AccR !valueR
        if (BlCompressType == 0x0B||BlCompressType == 0x0C){
            for(uint8_t i =137, e = primer +77; i<145 ; i++,e++){
                Transac[i] = bl2[(primer-60)+i];
            }
        }
            // !accL valueL !AccR !valueR
        if (BlCompressType == 0x0D){
            for(uint8_t i =137, e = primer +133; i<145 ; i++,e++){
                Transac[i] = bl2[(primer-4)+i];
            }
        }
            // !accL !valueL !AccR valueR
        if (BlCompressType == 0x0E){
            for(uint8_t i =137; i<141 ; i++){
                Transac[i] = 0;
            }
            for(uint8_t i =141; i<145 ; i++){
                Transac[i] = bl2[(primer-4)+i];
            }
        }
            // !accL valueL !AccR valueR
        if (BlCompressType == 0x0F){

            for(uint8_t i =137; i<141 ; i++){
                Transac[i] = 0;
            }
            for(uint8_t i =141; i<145 ; i++){
                Transac[i] = bl2[(primer-8)+i];
            }

        }
            // accL valueL !AccR !valueR
        if (BlCompressType == 0x10||BlCompressType == 0x13){
            for(uint8_t i =137; i<145 ; i++){
                Transac[i] = bl2[(primer-64)+i];
            }
        }

            // accL !valueL !AccR valueR
        if (BlCompressType == 0x11||BlCompressType == 0x14){

            for(uint8_t i =137; i<141 ; i++){
                Transac[i] = 0;
            }
            for(uint8_t i =141; i<145 ; i++){
                Transac[i] = bl2[(primer-64)+i];
            }

        }

            // accL valueL !AccR valueR
        if (BlCompressType == 0x12||BlCompressType == 0x15){

            for(uint8_t i =137; i<141 ; i++){
                Transac[i] = 0;
            }
            for(uint8_t i =141; i<145 ; i++){
                Transac[i] = bl2[(primer-68)+i];
            }

        }

            // accL !valueL AccR !valueR
        if (BlCompressType == 0x16){
            for(uint8_t i =137; i<145 ; i++){
                Transac[i] = bl2[(primer-120)+i];
            }
        }

            // accL valueL AccR !valueR
        if (BlCompressType == 0x17){
            for(uint8_t i =137; i<145 ; i++){
                Transac[i] = bl2[(primer-124)+i];
            }
        }

            // accL !valueL AccR valueR
        if (BlCompressType == 0x18){
            for(uint8_t i =137; i<141 ; i++){
                Transac[i] = 0;
            }
            for(uint8_t i =141; i<145 ; i++){
                Transac[i] = bl2[(primer-124)+i];
            }
        }

            // accL !valueL AccR valueR
        if (BlCompressType == 0x19){
            for(uint8_t i =137; i<141 ; i++){
                Transac[i] = 0;
            }
            for(uint8_t i =141; i<145 ; i++){
                Transac[i] = bl2[(primer-128)+i];
            }
        }
    

    //build  feed and numbertransac

            //if 1 acount Compressed
        if (BlCompressType == 0x0B||BlCompressType == 0x0C){
            for(uint8_t i =145; i<166 ; i++){
                Transac[i] = bl2[(primer-60)+i];
            }
        }

            //if 1 amount value Compressed
        if (BlCompressType == 0x0D||BlCompressType == 0x0E){
            for(uint8_t i =145; i<151 ; i++){
                Transac[i] = bl2[(primer-4)+i];
            }
        }

            //if 2 amount value Compressed
        if (BlCompressType == 0x0F){
            for(uint8_t i =145; i<166 ; i++){
                Transac[i] = bl2[(primer-8)+i];
            }
        }

            //if 1 Acc and 1 amount value Compressed
        if (BlCompressType == 0x10||BlCompressType == 0x11||BlCompressType == 0x13||BlCompressType == 0x14){
            for(uint8_t i =145; i<151 ; i++){
                Transac[i] = bl2[(primer-64)+i];
            }
        }

            //if 1 Acc and 2 amount value Compressed
        if (BlCompressType == 0x12||BlCompressType == 0x15){
            for(uint8_t i =145; i<166 ; i++){
                Transac[i] = bl2[(primer-68)+i];
            }
        }

            //if 2 Acc Compressed
        if (BlCompressType == 0x16){
            for(uint8_t i =145; i<166 ; i++){
                Transac[i] = bl2[(primer-120)+i];
            }
        }

            //if 2 Acc and 1 amount value Compressed
        if (BlCompressType == 0x17||BlCompressType == 0x18){
            for(uint8_t i =145; i<151 ; i++){
                Transac[i] = bl2[(primer-124)+i];
            }
        }

            //if 2 Acc and 2 amount value Compressed
        if (BlCompressType == 0x19){
            for(uint8_t i =145; i<166 ; i++){
                Transac[i] = bl2[(primer-128)+i];
            }
        }
    

    } else {

            // accL !valueL
        if (BlCompressType == 0x0B||BlCompressType == 0x11||BlCompressType == 0x16||BlCompressType == 0x18){
            for(uint8_t i =137; i<145 ; i++){
                Transac[i] = bl2[(primer-132)+i];
            }
        }
            // !accL !valueL
        if (BlCompressType == 0x04||BlCompressType == 0x0C||BlCompressType == 0x0E||BlCompressType == 0x14){
            for(uint8_t i =137; i<145 ; i++){
                Transac[i] = bl2[(primer-72)+i];
            }
        }
            // !accL valueL
        if (BlCompressType == 0x0D||BlCompressType == 0x0F||BlCompressType == 0x13||BlCompressType == 0x15){
            for(uint8_t i =137; i<141 ; i++){
                Transac[i] = 0;
            }
            for(uint8_t i =141; i<145 ; i++){
                Transac[i] = bl2[(primer-76)+i];
            }
        }
            // accL valueL
        if (BlCompressType == 0x10||BlCompressType == 0x12||BlCompressType == 0x17||BlCompressType == 0x19){
            for(uint8_t i =137; i<141 ; i++){
                Transac[i] = 0;
            }
            for(uint8_t i =141; i<145 ; i++){
                Transac[i] = bl2[(primer-136)+i];
            }
        }

    // building  feed and number transac

        // nothing compress
        if (BlCompressType == 0x04){
            for(uint8_t i =145; i<151 ; i++){
                Transac[i] = bl2[(primer-8)+i];
            }
        }
        // 1 acc compress
        if (BlCompressType == 0x0B || BlCompressType == 0x0C|| BlCompressType == 0x11 || BlCompressType == 0x14 ){
            for(uint8_t i =145; i<151 ; i++){
                Transac[i] = bl2[(primer-68)+i];
            }
        }

        // 1 value compress
        if (BlCompressType == 0x0D || BlCompressType == 0x0E || BlCompressType == 0x0F){
            for(uint8_t i =145; i<151 ; i++){
                Transac[i] = bl2[(primer-12)+i];
            }
        }

        // 1 acc & 1 value compress
        if (BlCompressType == 0x10  || BlCompressType == 0x12|| BlCompressType == 0x13|| BlCompressType == 0x15){
            for(uint8_t i =145; i<151 ; i++){
                Transac[i] = bl2[(primer-72)+i];
            }
        }

        // 2 acc compress
        if (BlCompressType == 0x16|| BlCompressType == 0x18){
            for(uint8_t i =145; i<151 ; i++){
                Transac[i] = bl2[(primer-128)+i];
            }
        }

        // 2 acc & 1 compress
        if (BlCompressType == 0x17|| BlCompressType == 0x19){
            for(uint8_t i =145; i<151 ; i++){
                Transac[i] = bl2[(primer-132)+i];
            }
        }



    }


    BuildHiddenData(bl2,last ,Transac);

    return ;
}

uint8_t AccIndexCompare2(vector<unsigned char>&bl2,uint &primer, array<unsigned char, 64 > &acc) {

    uint8_t result =0;

    if(bl2[primer]==0||bl2[primer]==4||bl2[primer]==6||bl2[primer]==8||bl2[primer]==0x0E){
        for(uint i = 0,e = primer+1;i<64;i++,e++){
            if(acc[i]!=bl2[e]){
                break;
            }
            if(i==63){
                result = 1;
            }
        }
        for(uint i = 0,e = primer+73;i<64;i++,e++){
            if(acc[i]!=bl2[e]){
                break;
            }
            if(i==63){
                result =  2;
            }
        }
        return result;
    }

    if(bl2[primer]==0x0B||bl2[primer]==0x11){

        for(uint i = 0,e = primer+13;i<64;i++,e++){
            if(acc[i]!=bl2[e]){
                break;
            }
            if(i==63){
                result =  2;
            }
        }
        return result;
    }

    if(bl2[primer]==0x0C||bl2[primer]==0x13||bl2[primer]==0x14||bl2[primer]==0x15){

        for(uint i = 0,e = primer+1;i<64;i++,e++){
            if(acc[i]!=bl2[e]){
                break;
            }
            if(i==63){
                result =  1;
            }
        }
        return result;
    }

    if(bl2[primer]==0x0D||bl2[primer]==0x0F){

        for(uint i = 0,e = primer+1;i<64;i++,e++){
            if(acc[i]!=bl2[e]){
                break;
            }
            if(i==63){
                result =  2;
            }
        }
        return result;
        for(uint i = 0,e = primer+69;i<64;i++,e++){
            if(acc[i]!=bl2[e]){
                break;
            }
            if(i==63){
                result =  2;
            }
        }
        return result;
    }

    if(bl2[primer]==0x10||bl2[primer]==0x12){

        return result;
        for(uint i = 0,e = primer+9;i<64;i++,e++){
            if(acc[i]!=bl2[e]){
                break;
            }
            if(i==63){
                result =  2;
            }
        }
        return result;
    }

    return 3;

}

void BuildAccBFromDataTransacArr(unsigned char (&DataTransac)[247], array<unsigned char, 64> &acc,bool side){

    if(side){ 
	    for(uint8_t i =0;i<64;i++){
		    acc[i] = DataTransac[i+73];
            cout<< byteToHex2(DataTransac[i+73]);
        }
	} else {

        for(uint8_t i =0;i<64;i++){
		    acc[i] = DataTransac[i+1];
        }

    }
	return;
}

string builAccStringFromDataTransacArray(unsigned char (&DataTransac)[247] ,bool side){ 

    string DataAcc="";
    if(side){
        for(int i =73;i<137;i++){
            DataAcc+=byteToHex2(DataTransac[i]);
        }
    }else{
        for(int i =1;i<65;i++){
            DataAcc+=byteToHex2(DataTransac[i]);
        }
    }
    return DataAcc;

}

uint32_t BuildFeedOfTransacFromArray(unsigned char (&DataTransac)[247]){
    uint32_t result = 0;
    uint8_t startIndex = 147;
    for (size_t i = 0; i < 4; ++i) {
        cout<< byteToHex2(DataTransac[i+startIndex]) ;
    }
    for (size_t i = 0; i < 4; ++i) {
        result = (result << 8) | static_cast<uint32_t>(DataTransac[startIndex + i]);
    }
    return result;
}

string builFirmStringFromBuffer(vector<unsigned char> bl2, uint primerInit ){ 
    if(bl2[primerInit]== 0){
        string result = "";
        for(int i = primerInit+151; i<primerInit+151+64; i++){
            result += byteToHex(bl2[i]);
        }
         for (auto &s : result){s = toupper(s);}
        return result;
    }
    return "null";
}

void builAccfromaccIndexing(array<unsigned char, 128> DataAccs,array<unsigned char, 64> &Acc,bool side){ 

    if(side){
        for(int i =64;i<128;i++){
            Acc[i]=DataAccs[i];
        }
    }else{
        for(int i =0;i<64;i++){
            Acc[i]=DataAccs[i];
        }
    }
    return ;

}

array<unsigned char, 64> builFirmArrayFromBuffer(vector<unsigned char> bl2, uint primerInit ){ 

    array<unsigned char, 64> arr;
    if(bl2[primerInit]== 0){
        uint e = 0;
        for(int i = primerInit+151; i<primerInit+211; i++){
            arr[e++]= bl2[i];
        }
        return arr;
    }
    return arr;
}

void builSignaturePointerFromBuffer(vector<unsigned char> &bl2, uint &primerInit, unsigned char (&signature)[64] ){ 

    cout<<endl<<"builSignaturePointerFromBuffer bl2[primerInit] "<< byteToHex(bl2[primerInit])<<endl;

    if(bl2[primerInit]== 0x04){
        uint e = 0;
        for(uint i = primerInit+143; i<primerInit+207; i++){
            signature[e++]= bl2[i];
        }
        return ;
    }
    if(bl2[primerInit]== 0x1B|| bl2[primerInit]== 0x1A){
        uint e = 0;
        for(uint i = primerInit+83; i<primerInit+147; i++){
            signature[e++]= bl2[i];
        }
        return ;
    }
    if(bl2[primerInit]== 0x1C){
        uint e = 0;
        for(uint i = primerInit+139; i<primerInit+203; i++){
            signature[e++]= bl2[i];
        }
        return ;
    }
    
    if(bl2[primerInit]== 0x1F || bl2[primerInit]== 0x22 ){
        uint e = 0;
        for(uint i = primerInit+79; i<primerInit+143; i++){
            signature[e++]= bl2[i];
        }
        return ;
    }

    if(bl2[primerInit]== 0x25 ){
        uint e = 0;
        for(uint i = primerInit+23; i<primerInit+87; i++){
            signature[e++]= bl2[i];
        }
        return ;
    }

    if(bl2[primerInit]== 0x26 ){
        uint e = 0;
        for(uint i = primerInit+19; i<primerInit+83; i++){
            signature[e++]= bl2[i];
        }
        return ;
    }

    uint8_t bltype = getBlCompressType(bl2[primerInit]); 


    if(bltype== 0x00){
        uint e = 0;
        for(uint i = primerInit+151; i<primerInit+215; i++){
            signature[e++]= bl2[i];
        }
        return ;
    }

    if(bltype== 0x0B|| bltype== 0x0C){
        uint e = 0;
        for(uint i = primerInit+91; i<primerInit+91+64; i++){
            signature[e++]= bl2[i];
        }
        return ;
    }

    if(bltype== 0x0D|| bltype== 0x0E){
        uint e = 0;
        for(uint i = primerInit+147; i<primerInit+147+64; i++){
            signature[e++]= bl2[i];
        }
        return ;
    }

    if(bltype== 0x0F){
        uint e = 0;
        for(uint i = primerInit+143; i<primerInit+143+64; i++){
            signature[e++]= bl2[i];
        }
        return ;
    }

    if(bltype== 0x10|| bltype== 0x11|| bltype== 0x13|| bltype== 0x14){
        uint e = 0;
        for(uint i = primerInit+87; i<primerInit+87+64; i++){
            signature[e++]= bl2[i];
        }
        return ;
    }

    if(bltype== 0x12|| bltype== 0x15){
        uint e = 0;
        for(uint i = primerInit+83; i<primerInit+83+64; i++){
            signature[e++]= bl2[i];
        }
        return ;
    }
    if(bltype== 0x16){
        uint e = 0;
        for(uint i = primerInit+31; i<primerInit+31+64; i++){
            signature[e++]= bl2[i];
        }
        return ;
    }
    if(bltype== 0x17|| bltype== 0x18){
        uint e = 0;
        for(uint i = primerInit+27; i<primerInit+91; i++){
            signature[e++]= bl2[i];
        }
        return ;
    }
    if(bltype== 0x19){
        uint e = 0;
        for(uint i = primerInit+23; i<primerInit+23+64; i++){
            signature[e++]= bl2[i];
        }
        return ;
    }
}

void builPublicSignerPointer(array<unsigned char, 128> DataAccs, unsigned char (&PublicSigner)[] ){ 

    for(int i = 0; i<64; i++){
        PublicSigner[i]= DataAccs[i];
    }
    return ;
    
}

bool PrimerChange(uint8_t bltype, uint &primer){

    switch (bltype){
        case 0x04:
            primer+=207;
            return true;
        case 0x1A:
        case 0x1B:
            primer+=147;
            return true;
        case 0x1C:
            primer+=203;
            return true;
        case 0x1F:
        case 0x22:
            primer+=143;
            return true;
        case 0x25:
            primer+=87;
            return true;
        case 0x26:
            primer+=83;
            return true;
        default:
            break;
    }

    bltype = getBlCompressType(bltype);

    switch (bltype){
        case 0:
            primer+=215;
            break;
        case 0x0B:
        case 0x0C:
            primer+=155;
            break;
        case 0x0D:
        case 0x0E:
            primer+=211;
            break;
        case 0x0F:
            primer+=207;
            break;
        case 0x10:
        case 0x11:
        case 0x13:
        case 0x14:
            primer+=151;
            break;
        case 0x12:
        case 0x15:
            primer+=147;
            break;
        case 0x16:
            primer+=95;
            break;
        case 0x17:
        case 0x18 :
            primer+=91;
            break;
        case 0x19 :
            primer+=87;
            break;

        default:
            cout<<endl<<"error indexing data DB "<< unsignedCharToHex( bltype);
            exit_call();
            return false;
    }



    return true;
}

uint8_t AccIndexCompare3(vector<unsigned char>& bl2,uint &primer,uint64_t &last, array<unsigned char, 64 > &acc,vector<string> &accB , uint16_t &DataCompressIndex) {

    accB.clear();
    uint64_t lastblb = lastbl;
    uint8_t blType = getBlCompressType(bl2[primer]);

    // cout<<endl<< " AccIndexCompare3 type transac debug type "<< constByteToHex2( blType) <<endl;

    //Normal transac
    if(blType==0x00||blType==0x04||blType==0x06||blType==0x08||blType==0x0E){

        //Check if Acc indexing is on accRPoint
        for(uint8_t i = 0;i<64;i++){
            if(acc[i]!=bl2[primer +73+i]){
                break;
            }
            if(i==63){
                string accBStr="";
                for(int i = 0; i<64; i++){
                    accBStr+= byteToHex(bl2[primer +1+i]);
                }
                uint16_t CompressedPointBL = 0;
                accB.push_back(accBStr);
                DataCompressIndex = dataCompressIndex(lastblb, last,false, CompressedPointBL);

                return 2;
            }
        }

        //Check if Acc indexing is on accLPoint
        for(uint8_t i = 0;i<64;i++){
            if(acc[i]!=bl2[primer +1+i]){
                break;
            }
            if(i==63){
                string accBStr="";
                for(int i = 0; i<64; i++){
                    accBStr+= byteToHex(bl2[primer +73+i]);
                }
            accB.push_back(accBStr);
            uint16_t CompressedPointBL = 0;
            DataCompressIndex = dataCompressIndex(lastblb, last,false, CompressedPointBL);
            return 1;
            }
        }

        return 0;
    }

    //accl compress
    if(blType==0x0B||blType==0x11){

        uint8_t compressedPoint[4];
        getCompressedPointBlTransac(bl2,compressedPoint,primer,false);
        uint16_t CompressedPointBL = (static_cast<uint16_t>(compressedPoint[0]) << 8) | compressedPoint[1];

        //Check if Acc indexing is on accRPoint
        //build accL accounts in vector to firm verifier
        for(int i = 0;i<64;i++){

            if( acc[i] != bl2[primer +13+i]){
                break;
            }

            if(i==63){

                buildAccbVector(accB ,last,compressedPoint);
                CompressedPointBL = 0;
                DataCompressIndex = dataCompressIndex(lastblb, last,false, CompressedPointBL);
                return 2;
            }

        }

        //Check if Acc indexing is on accLPoint

        uint16_t CompressAccBl = (static_cast<uint16_t>(compressedPoint[2]) << 8) | compressedPoint[3];
        uint16_t CompressAcc = (static_cast<uint16_t>(acc[62]) << 8) | acc[63];

        //cout<<endl<<"debug acc index compare3 CompressAccBl "<< CompressAccBl<<" CompressAcc "<<CompressAcc<<endl;

        if(CompressAccBl==CompressAcc){

            if(CompressedPointBL>last || last - CompressedPointBL> last ){
                cout<<endl<<"error AccIndexCompare3 CompressedPointBL>last || last - CompressedPointBL> last"<<endl;
                exit_call();
            }

            string accBStr="";
            for(int i = 0; i<64; i++){
                accBStr+= byteToHex2(bl2[primer +13+i]);
            }
            accB.push_back(accBStr);

            DataCompressIndex = dataCompressIndex(lastblb, last,true, CompressedPointBL);
            //cout<<endl<<"debug this DataCompressIndex "<<to_string(DataCompressIndex)<<endl;
            return 1;
        }

        return 0;

    }

    //AccR compress
    if(blType==0x0C||blType==0x14||blType==0x13||blType==0x15){
 
        uint8_t compressedPoint[4];
        getCompressedPointBlTransac(bl2,compressedPoint,primer,true);

        //Check if Acc indexing is on acclPoint
        for(int i = 0;i<64;i++){
            if(acc[i]!=bl2[primer +1+i]){
                break;
            }
            if(i==63){
                //if acc is found in accLpoint
                //buld accB vector with accR
                buildAccbVector(accB ,last,compressedPoint);
                uint16_t CompressedPointBL = 0;
                DataCompressIndex = dataCompressIndex(lastblb, last,false, CompressedPointBL);
                return 1;

            }
        }

        //Check if Acc indexing is on accRPoint
        uint16_t CompressedPointBL = (static_cast<uint16_t>(compressedPoint[0]) << 8) | compressedPoint[1];
        uint16_t CompressAccBl = (static_cast<uint16_t>(compressedPoint[2]) << 8) | compressedPoint[3];
        uint16_t CompressAcc = (static_cast<uint16_t>(acc[62]) << 8) | acc[63];

        if(CompressAccBl==CompressAcc){
            if(CompressedPointBL>last || last - CompressedPointBL> last ){
                cout<<endl<<"error AccIndexCompare3 CompressedPointBL>last || last - CompressedPointBL> last"<<endl;
                exit_call();
            }

            string accBStr="";
            for(int i = 1; i<65; i++){
                accBStr+= byteToHex2(bl2[primer+i]);
            }
            accB.push_back(accBStr);
            DataCompressIndex = dataCompressIndex(lastblb, last, true,CompressedPointBL );
            return 2;
            
        }

        return 0;

    }

    //valueL compress
    if(blType==0x0D||blType==0x0F){

        //Check if Acc indexing is on accLPoint
        for(uint8_t i = 0;i<64;i++){
            if(acc[i]!=bl2[primer +1+i]){
                break;
            }
            if(i==63){
                string accBStr="";
                for(int i = 0; i<64; i++){
                    accBStr+= byteToHex(bl2[primer +69+i]);
                }
                accB.push_back(accBStr);
                uint16_t CompressedPointBL = 0;
                DataCompressIndex = dataCompressIndex(lastblb, last,false, CompressedPointBL);

                return 1;
            }
        }

        //Check if Acc indexing is on accRPoint
        for(uint8_t i = 0;i<64;i++){
            if(acc[i]!=bl2[primer +69+i]){
                break;
            }
            if(i==63){
                string accBStr="";
                for(int i = 0; i<64; i++){
                    accBStr+= byteToHex(bl2[primer +1+i]);
                }
                accB.push_back(accBStr);
                uint16_t CompressedPointBL = 0;
                DataCompressIndex = dataCompressIndex(lastblb, last,false, CompressedPointBL);
                return 2;
            }
        }
        return 0;
    }

    //AccL and ValueL compress
    if(blType==0x10||blType==0x12){
 
        uint8_t compressedPoint[4];
        getCompressedPointBlTransac(bl2,compressedPoint,primer,false);
        
        //Check if Acc indexing is on accRPoint
        // build accL accounts in vector to firm verifier
        for(int i = 0;i<64;i++){
            if(acc[i]!=bl2[primer +9+i]){
                break;
            }
            if(i==63){
                buildAccbVector(accB ,last,compressedPoint);
                uint16_t CompressedPointBL=0;
                DataCompressIndex = dataCompressIndex(lastblb, last,false, CompressedPointBL);
                return 2;
            }
        }

        //Check if Acc indexing is on accLPoint
        uint16_t CompressedPointBL = (static_cast<uint16_t>(compressedPoint[0]) << 8) | compressedPoint[1];
        uint16_t CompressAccBl = (static_cast<uint16_t>(compressedPoint[2]) << 8) | compressedPoint[3];
        uint16_t CompressAcc = (static_cast<uint16_t>(acc[62]) << 8) | acc[63];
        if(CompressAccBl==CompressAcc){
            if(CompressedPointBL>last || last - CompressedPointBL> last ){
                cout<<endl<<"error AccIndexCompare3 CompressedPointBL>last || last - CompressedPointBL> last"<<endl;
                exit_call();
            }

            string accBStr="";
            for(int i = 0; i<64; i++){
                accBStr+= byteToHex(bl2[primer +9+i]);
            }
            accB.push_back(accBStr);

            DataCompressIndex = dataCompressIndex(lastblb, last, true,CompressedPointBL );
            return 1;

        }

        return 0;

    }

    //accR ValueL compress
    /*
    if(bl2[primer]==0x13||bl2[primer]==0x15){
 
        uint8_t compressedPoint[4];
        getCompressedPointBlTransac(bl2,compressedPoint,primer,true);

        //Check if Acc indexing is on accLPoint
        for(int i = 0;i<64;i++){
            if(acc[i]!=bl2[primer +1+i]){
                break;
            }
            if(i==63){
                //if acc is found in accLpoint
                //buld accB vector with accR
                
                buildAccbVector(accB ,last,compressedPoint);
                uint16_t CompressedPointBL = 0;
                DataCompressIndex = dataCompressIndex(lastblb, last,false, CompressedPointBL);
                return 1;

            }
        }

        //Check if Acc indexing is on accRPoint
        uint16_t CompressedPointBL = (static_cast<uint16_t>(compressedPoint[0]) << 8) | compressedPoint[1];
        uint16_t CompressAccBl = (static_cast<uint16_t>(compressedPoint[2]) << 8) | compressedPoint[3];
        uint16_t CompressAcc = (static_cast<uint16_t>(acc[62]) << 8) | acc[ 63];
        if(CompressAccBl==CompressAcc){
            cout<<endl<<"debug AccIndexCompare3 CompressAccBl==CompressAcc R side bltype:"<<byteToHex2(bl2[primer])<<endl;
            if(CompressedPointBL>last || last - CompressedPointBL> last ){
                cout<<endl<<"error AccIndexCompare3 CompressedPointBL>last || last - CompressedPointBL> last"<<endl;
                exit_call();
            }
            
            //if acc is found in accRpoint
            //buld accB vector with accL
            //getCompressedPointBlTransac(bl2,compressedPoint,primer,false);

            string accBStr="";
            for(int i = 1; i<65; i++){
                accBStr+= byteToHex2(bl2[primer+i]);
            }
            accB.push_back(accBStr);
            DataCompressIndex = dataCompressIndex(lastblb, last,true, CompressedPointBL);
            return 2;

            
        }

        return 0;

    }
*/
    //accL & accR compress
    if(blType==0x16||blType==0x18||blType==0x17||blType==0x19){ 

        //Check if Acc indexing is on accLPoint
        uint8_t compressedPoint[4];
        getCompressedPointBlTransac(bl2,compressedPoint,primer,false);
        uint16_t CompressedPointBL = (static_cast<uint16_t>(compressedPoint[0]) << 8) | compressedPoint[1];
        uint16_t CompressAccBl = (static_cast<uint16_t>(compressedPoint[2]) << 8) | compressedPoint[3];
        uint16_t CompressAcc = (static_cast<uint16_t>(acc[62]) << 8) | acc[63];
        
        if(CompressAccBl==CompressAcc){
            if(CompressedPointBL>last || last - CompressedPointBL> last ){
                cout<<endl<<"error AccIndexCompare3 CompressedPointBL>last || last - CompressedPointBL> last"<<endl;
                exit_call();
            }
            cout<<endl<<"debug AccIndexCompare3 CompressAccBl==CompressAcc Lside bltype: "<<byteToHex2(bl2[primer])<<endl;

            getCompressedPointBlTransac(bl2,compressedPoint,primer,true);

            //searchUncompressAccInBl(acc, last - CompressedPointBL)
            if(buildAccbVector(accB ,last,compressedPoint)){
                cout<<" pass"<<endl;
                //if acc is found in accLpoint
                //buld accB vector with accR
                //getCompressedPointBlTransac(bl2,compressedPoint,primer,true);

                
                DataCompressIndex = dataCompressIndex(lastblb, last,true, CompressedPointBL);
                return 1;

            }
            cout<<" fail"<<endl;
        }

        //Check if Acc indexing is on accRPoint
        getCompressedPointBlTransac(bl2,compressedPoint,primer,true);
        CompressedPointBL = (static_cast<uint16_t>(compressedPoint[0]) << 8) | compressedPoint[1];
        CompressAccBl = (static_cast<uint16_t>(compressedPoint[2]) << 8) | compressedPoint[3];
        CompressAcc = (static_cast<uint16_t>(acc[62]) << 8) | acc[ 63];
        if(CompressAccBl==CompressAcc){
            cout<<endl<<"debug AccIndexCompare3 CompressAccBl==CompressAcc R side bltype:"<<byteToHex2(bl2[primer])<<endl;
            if(CompressedPointBL>last || last - CompressedPointBL> last ){
                cout<<endl<<"error AccIndexCompare3 CompressedPointBL>last || last - CompressedPointBL> last"<<endl;
                exit_call();
            }
            getCompressedPointBlTransac(bl2,compressedPoint,primer,false);
            if( buildAccbVector(accB ,last,compressedPoint) ){

                //if acc is found in accRpoint
                //buld accB vector with accL
                //getCompressedPointBlTransac(bl2,compressedPoint,primer,false);
                
                DataCompressIndex = dataCompressIndex(lastblb, last,true, CompressedPointBL);
                return 2;

            }
        }

        return 0;

    }

    cout<<endl<<"error AccIndexCompare3 bad primer "<< byteToHex2(blType)<<endl;
    exit_call();
    return 3;

}


string buildtransacString(vector<string> &accA, vector<string> &accB, vector<unsigned char> &bl2,uint &primerInit, uint64_t &last){

    unsigned char DataTransac[247];
    unsigned char signature[64];
    string datatransacstring="";
    string signaturestring="";
    array<unsigned char, 64> acc = accArr(accA[0]);
    
    buildTransacPointerFromBuffer(bl2,acc,primerInit,last, DataTransac);
    builSignaturePointerFromBuffer(bl2,primerInit,signature);
    for(uint8_t i =0;i<247;i++){
        datatransacstring +=byteToHex2(DataTransac[i]);
    }
    for(uint8_t i =0;i<64;i++){
        signaturestring+=byteToHex2(signature[i]);
    }

    uint16_t accAsize = accA.size();
    uint16_t accBsize = accB.size();
    uint16_t accANumberVector;
    uint16_t accBNumberVector;

    for( accANumberVector= 0; accANumberVector< accAsize; accANumberVector++){
        
        for( accBNumberVector= 0; accBNumberVector< accBsize; accBNumberVector++){

            datatransacstring = datatransacstring.substr(0,2)+accA[accANumberVector].substr(0,128)+datatransacstring.substr(130,16)+accB[accBNumberVector].substr(0,128)+datatransacstring.substr(274,datatransacstring.length()-274);
            for (auto &s : datatransacstring){s = toupper(s);}

           // cout<<endl<<"buildtransacin vector debug datatransacstring " << datatransacstring<< endl;

            if(!verifySignature(  datatransacstring, signaturestring, loadPublicKey(datatransacstring.substr(2,128) ))){
                continue;
            }else {

                return datatransacstring+signaturestring;

            }
        }
        
        if(accANumberVector==accAsize-1){
            cout<<endl<<"error buildTransacStr!, Firm is False"<<endl;
            exit_call();
        }

    }
    cout<<endl<<"error buildTransacStr!";
    exit_call();
    return "error buildTransacStr!";

}

string buildtransacCheckString(vector<string> &accA, vector<string> &accB, vector<unsigned char> &bl2,uint &primerInit, uint64_t &last, uint16_t &index){

    unsigned char DataTransac[247];
    unsigned char signature[64];
    string datatransacstring="";
    string signaturestring="";
    array<unsigned char, 64> acc = accArr(accA[0]);
    
    buildTransacPointerFromBuffer(bl2,acc,primerInit,last, DataTransac);
    builSignaturePointerFromBuffer(bl2,primerInit,signature);
    for(uint8_t i =0;i<247;i++){
        datatransacstring +=byteToHex2(DataTransac[i]);
    }
    for(uint8_t i =0;i<64;i++){
        signaturestring+=byteToHex2(signature[i]);
    }

    uint16_t accAsize = accA.size();
    uint16_t accBsize = accB.size();
    uint16_t accANumberVector;
    uint16_t accBNumberVector;

    for( accANumberVector= 0; accANumberVector< accAsize; accANumberVector++){
        
        for( accBNumberVector= 0; accBNumberVector< accBsize; accBNumberVector++){

            datatransacstring = datatransacstring.substr(0,2)+accA[accANumberVector].substr(0,128)+datatransacstring.substr(130,16)+accB[accBNumberVector].substr(0,128)+datatransacstring.substr(274,datatransacstring.length()-274);
            for (auto &s : datatransacstring){s = toupper(s);}

            cout<<endl<<"buildtransacin vector debug datatransacstring " << datatransacstring<< endl;

            if(!verifySignature(  datatransacstring, signaturestring, loadPublicKey(datatransacstring.substr(2,128) ))){
                continue;
            }else {
                acc = accArr(accA[accANumberVector]);
                if(checkSumsBalances(bl2,acc,DataTransac,accB[accBNumberVector], primerInit, last, index, true)){                    
                    return datatransacstring.substr(0,302)+signaturestring;
                } else { 
                    cout<<endl<<"error buildTransacStr!";
                    exit_call();
                }
            }

        }
        
        if(accANumberVector==accAsize-1){
            cout<<endl<<"error buildTransacStr!, Firm is False"<<endl;
            exit_call();
        }

    }
    cout<<endl<<"error buildTransacStr!";
    exit_call();
    return "error buildTransacStr!";

}

string transacbynunmbr(uint64_t blnumber, uint transacNumber ){



    vector<unsigned char> bl2;
    blread2(to_string(blnumber),bl2);
    int qttblks = hexToULL(blkscontain2(bl2));


    
    int transacsMaxIndex = qttblks;
    int transacIndex = 0;
    int Signersqty2=signersqty2(bl2);
    
    int primerPosition =  187+(34*Signersqty2); 

    string str1= "0101";
    string str2;
    string bl = bytesToHexStr(bl2);

    for (int i = 0;i <2; i++ ){
        str2+= byteToHex(bl2[primerPosition+i]) ;
    }

    int primerBlStr = (primerPosition+2);

    if(transacNumber>1){
       primerBlStr= primerBlStr+(258*(transacNumber-1));
    }

    if(str1!=str2 ){
        return "some error";
    }

    str2 = "";

    string transac="";

    for (int i = 0;i <256;i++){
        transac += byteToHex(bl2[primerBlStr+i]);
    } 

    cout<<endl<<"transac by number debug "<<transac<<endl;

    primerPosition = primerPosition + 258;

    for (int i = 0;i <2;i++){
        str2 += byteToHex(bl2[primerPosition+i]);
    }   
    
    if ( str2 != "0101" && str2 != "9696"){
        cout<<endl<<"Read_Error SLM str2 "<<str2<<endl;
        transac= "error SLM str2 ";
        return "error SLM str2 ";
    }   

    for (auto &s : transac){s = toupper(s);}
    cout<<endl<<"debug index transac "<<transac<<endl;
    return transac;

}

string transacIdHash(uint64_t blnumber, uint transacNumber){

   return SHAstg(transacbynunmbr(blnumber,transacNumber));

}

string transacByNumer2(uint64_t blnumber, uint16_t transacNumber){

    if(blnumber<1 || blnumber> lastbl ){return "error from transacHash: blnumber<1 ||transacNumber<1";}

    vector<unsigned char> bl2;
    blread2(to_string(blnumber),bl2);
    uint qttblks = hexToULL(blkscontain2(bl2));
    uint primer = 179;

    vector<string> accA;
    vector<string> accB;

    if(transacNumber<1 || transacNumber> qttblks ){return "qttytransacs<1 || transacNumber=> qttytransacs";}

    for(uint16_t i = qttblks ; i > transacNumber; i-- ){
        PrimerChange(bl2[primer],primer );
    }

    accsvectorbuilder(bl2,blnumber, primer,accA,accB);
    return buildtransacString(accA, accB, bl2,primer, blnumber);

}

string transacIdHash2(uint64_t blnumber, uint transacNumber){

   return SHAstg(transacByNumer2(blnumber,transacNumber));

}

void ClearOpBlks(){

    extern mutex queueIpMtx;
    extern mutex writingspace;
    extern mutex queuetransacsmtx;
    extern mutex MatchminTransacsmtx;
    extern mutex pricesingtransacCount;
    extern mutex blkQueuemtx;

    extern string* blksOP;
    extern time_t* transactime;
    extern string F256;
    extern const uint16_t maxblksize;

    extern vector<string>blksOPSync;
    extern vector <string> queueIp;
    extern map<string, string> queuetransacs;
    extern map<int,bool>checkTransacSync;
    extern mutex WritingAccSync;
    extern uint syncOpNumbr;
    extern uint wirtespacecount;
    extern int32_t transacscomfirmed;
    extern int32_t transacpendingcount;
    extern int32_t pretransacpending;
    extern map< array <unsigned char,64>, Accsync >AccSync;

    



    std::unique_lock<std::mutex> writingspacelock(writingspace);
    for(uint16_t i = 0; i<maxblksize; i++){
        blksOP[i]= F256;
        transactime[i]= 9999;
    }
    writingspacelock.unlock();

    std::unique_lock<std::mutex> blkQueuemtxlock(blkQueuemtx);
    blksOPSync.clear();
    checkTransacSync.clear();
    numberspace.clear();
    blkQueuemtxlock.unlock();

    std::unique_lock<std::mutex> queueIpMtxlock(queueIpMtx);
    queueIp.clear();
    queueIpMtxlock.unlock();

    std::unique_lock<std::mutex> WritingAccSynclock(WritingAccSync);
    AccSync.clear();
    WritingAccSynclock.unlock();

    std::unique_lock<std::mutex> queuetransacsmtxlock(queuetransacsmtx);
    queuetransacs.clear();
    queuetransacsmtxlock.unlock();

    std::unique_lock<std::mutex> MatchminTransacsmtxlock(MatchminTransacsmtx);
    MatchminTransacs.clear();
    MatchminTransacsmtxlock.unlock();

    std::unique_lock<std::mutex> pricesingtransacCountlock(pricesingtransacCount);

    syncOpNumbr = 0;
    wirtespacecount =0;
    transacscomfirmed = 0;
    transacpendingcount = 0;
    pretransacpending = 0;

    cout<<endl<<endl<<"ClearOpBlks() end"<<endl<<endl;

}

string readHash(string &stg){
   return stg.substr(0, 64);   
}

string readTransacFirmString(string &stg){
return stg.substr(302, 128);
}

string dataTransacString(string& stg){
return stg.substr(0, 372);
}

string readaccountString(string stg, bool side){

    if(side){
        return stg.substr(146, 128);
    }else{
        return stg.substr(2, 128);
    }

    cout<<endl<<" readaccountString error bool side null";
    exit_call(); 
}

string readbalanceString(string stg, bool side){

    if(side){
        return stg.substr(274, 16);
    } else {
        return stg.substr(130, 16);
    }
    cout<<endl<<" error readbalanceString bool side null";
    exit_call(); 
    return "";
}

uint64_t readbalanceuint64(string &stg, bool side){
    if(side){
        return hexToULL( stg.substr(274, 16));
    }else{
        return hexToULL( stg.substr(130, 16));
    }
    return 0;
}

string blOpNmbr(string stg){
    return stg.substr(290, 4);
}

////// hidden
//
string ShaMinNode(string &stg){
    return stg.substr(512, 64);
}

string FeedOfTransac(string stg){
    return stg.substr(294, 8);
}

void changeBlNmbr(string &stg , string nmbr){
    stg = stg.substr(0, 290) + nmbr + stg.substr(294, stg.length()-294 );
}

bool changeBlType(string &stg , string BlType,string &value){

    if(BlType.length()!= 2 || value.length()!= 16  ){
        return false;
    }

    stg = BlType +  stg.substr(2,stg.length()-2);

    if( BlType == "02" || BlType == "00" || BlType == "FF" ){return true; }

    if(BlType == "03"||BlType =="04"){
        stg = stg.substr(0,130) + value + stg.substr(146,128)+value+stg.substr(290,stg.length()-290);
        return true;
    }

    if(BlType == "05"||BlType =="06"){
        stg = stg.substr(0,130) + readbalanceString(stg, "L") + stg.substr(146,128)+value+stg.substr(290,stg.length()-290);
        return true;
    }
    if(BlType == "07"||BlType =="08"){
        stg = stg.substr(0,130) + value +  stg.substr(146,128)+readbalanceString(stg, "R")+stg.substr(290,stg.length()-290);
        return true;
    }

    stg = stg.substr(0,130) + value  + stg.substr(146,128)+ value+ stg.substr(290,stg.length()-290);

    return false;

}

string switchBlType(string &stg){

    string BlType;

    if(typebl(stg) == "00"){
        BlType = "02";
    }
    if(typebl(stg) == "02"){
        BlType = "00";
    }
    if(typebl(stg) == "03"){
        BlType = "04";
    }
    if(typebl(stg) == "04"){
        BlType = "03";
    }
    if(typebl(stg) == "05"){
        BlType = "06";
    }
    if(typebl(stg) == "06"){
        BlType = "05";
    }
    if(typebl(stg) == "07"){
        BlType = "08";
    }
    if(typebl(stg) == "08"){
        BlType = "07";
    }

    return BlType +  stg.substr(2,stg.length()-2);

}

bool  buildTransacInVector(vector<string> &accA, vector<string> &accB, vector<unsigned char> &bl2,uint &primerInit, uint64_t &last, uint16_t &index, vector<unsigned char>&UncompressedBl){
    addHexStringInVector( UncompressedBl, buildtransacCheckString(accA, accB, bl2,primerInit, last, index));
    return true;
}

bool chcktransac(vector<string> &accA, vector<string> &accB, vector<unsigned char> &bl2,uint &primerInit, uint64_t &last, uint16_t &index ){

    unsigned char DataTransac[247];
    unsigned char signature[64];
    string datatransacstring="";
    string signaturestring="";
    array<unsigned char, 64> acc = accArr(accA[0]);
    
    buildTransacPointerFromBuffer(bl2,acc,primerInit,last, DataTransac);
    builSignaturePointerFromBuffer(bl2,primerInit,signature);
    for(int i =0;i<247;i++){
        datatransacstring +=byteToHex2(DataTransac[i]);
    }
    for(int i =0;i<64;i++){
        signaturestring+=byteToHex2(signature[i]);
    }

    uint16_t accAsize = accA.size();
    uint16_t accBsize = accB.size();
    uint16_t accANumberVector;
    uint16_t accBNumberVector;

    for( accANumberVector= 0; accANumberVector< accAsize; accANumberVector++){
        
        for( accBNumberVector= 0; accBNumberVector< accBsize; accBNumberVector++){

            datatransacstring = datatransacstring.substr(0,2)+accA[accANumberVector].substr(0,128)+datatransacstring.substr(130,16)+accB[accBNumberVector].substr(0,128)+datatransacstring.substr(274,datatransacstring.length()-274);
            for (auto &s : datatransacstring){s = toupper(s);}

            if(!verifySignature(  datatransacstring, signaturestring, loadPublicKey(datatransacstring.substr(2,128) ))){
                continue;
            }else {
                cout<<endl<<"ckeck firm success";
                acc = accArr(accA[accANumberVector]);
                if(checkSumsBalances(bl2,acc,DataTransac,accB[accBNumberVector], primerInit, last, index, true)){
                    return true;
                } else { 
                    return false;
                }
            }
        }
        
        if(accANumberVector==accAsize-1){
            cout<<endl<<"error chcktransac!, Firm False"<<endl;
            return false;
        }

    }
    return false;
}

bool build_blkschkbl(uint16_t &qttblks, vector<unsigned char> &bl2 ){ 

    blread2("dlsync/dl" ,bl2);
    qttblks = hexToULL(blkscontain2(bl2));
    uint primerInit=179;
    uint blsize  = bl2.size();

    for(uint i = 0 ; i<qttblks; i++){

        if(primerInit>blsize ){
            cout<<endl<<"error reading build_blkschkbl 1 "<<blsize<<endl;
            exit_call();
        }
        //cout<<endl<<"build_blkschkbl debug before bl2["<<primerInit<<"] "<<byteToHex2(bl2[primerInit])<<endl;
        PrimerChange(bl2[primerInit],primerInit );
        //cout<<endl<<"build_blkschkbl debug after primerchange "<<primerInit<<endl;
    }

    for (uint i = primerInit; i<primerInit+2;i++){
        if (byteToHex2( bl2[i]) != "96"){
            cout<<endl<<"error reading build_blkschkbl 3 "<< byteToHex2( bl2[i])<<endl;
            exit_call();
        }
    }

    //cout<<endl<<"debug build_blkschkbl qttblks "<<qttblks<<endl;
    return true;

}

bool checkblks (uint64_t &last){

    vector<unsigned char> bl2;
    uint primerInit = 179;
    uint qttblks;
    vector<string> accA;
    vector<string> accB;

    if(!build_blks( qttblks, last,  bl2)){
        return "error reading DB";
    }

    for(uint16_t a = qttblks; a>=1; a--){ 
        accsvectorbuilder(bl2,last,primerInit,accA,accB);
        if(!chcktransac(accA,accB,bl2,primerInit,last,a)){
            return false;
        }
        //cout<<endl<<"chcktransac success"<<endl;
        PrimerChange(bl2[primerInit], primerInit);
    }
    cout<<endl<<"checkblk; "<< last<< " success"<<endl;
    return true;
}

vector<unsigned char> read_blRefactHash(vector<unsigned char> &bl2 ){ 

    uint qttblks = hexToULL(blkscontain2(bl2));
    uint primerInit=179;
    uint blsize  = bl2.size();
    vector<unsigned char>blRefactHasheds;
    cout<<endl<<"qttt readed "<<qttblks<<endl;

    for(uint i = 0 ; i<qttblks; i++){

        if(primerInit>blsize ){
            cout<<endl<<"error reading build_lastblRefactHash 1 "<<endl;
            exit_call();
        }
        cout<<endl<<"bl2[primerInit] "<< byteToHex(bl2[primerInit]);
        cout<<endl<<"getBlCompressType bl2[primerInit] "<<byteToHex(getBlCompressType(bl2[primerInit]));
        PrimerChange(bl2[primerInit],primerInit );
    }

    for (uint32_t primerInitc = primerInit; primerInit<primerInitc+2;primerInit++){
        if (byteToHex2( bl2[primerInit]) != "96"){
            cout<<endl<<"error reading build_lastblRefactHash 2 "<<endl;
            exit_call();
        }
    }

    if (blsize!= primerInit+32){
        if (lastbl<1){
            extern vector<unsigned char>IdBlkchain;
            for(uint8_t i ; i<32 ; i++){
                blRefactHasheds.push_back(IdBlkchain[i]);
                return blRefactHasheds;
            }

        }else{
            cout<<endl<<"error reading build_lastblRefactHash 3 "<<blsize<<" "<<primerInit<<endl;
            exit_call();
        }
    }

    for(uint32_t primerInitc = primerInit; primerInit<primerInitc+32;primerInit++){
        blRefactHasheds.push_back(bl2[primerInit]);
    }


    return blRefactHasheds;

}

vector<unsigned char> LastblRefactUncompressedHashed(){

    vector<unsigned char>bl2;
    string str = to_string(lastbl);
    blread2(str ,bl2 );
    return read_blRefactHash(bl2);
}

vector<unsigned char> build_uncompressbl_secuCheck(uint64_t last){

    vector<unsigned char> bl2;
    vector<unsigned char>UncompressBL;
    vector<unsigned char>HashUncompressBL;
    uint primerInit = 179;
    uint qttblks;
    vector<string> accA;
    vector<string> accB;

    cout<<endl<<" build_uncompressbl_secuCheck init"<<endl;

    if(!build_blks( qttblks, last,  bl2)){
        cout<<endl<<"error build_uncompressbl_secuCheck() !build_blks"<<endl;
        exit_call();
        return UncompressBL;
    }

    cout<<endl<<" build_uncompressbl_secuCheck fl2"<<endl;


    for(uint8_t i=  0;i<179;i++){
        UncompressBL.push_back(bl2[i]);
    }



    for(uint16_t a = qttblks; a>=1; a--){ 

        cout<<endl<<"debug build_uncompressbl_secuCheck loop "<<endl;
        accsvectorbuilder(bl2,last,primerInit,accA,accB);

        if(!buildTransacInVector(accA,accB,bl2,primerInit,last,a , UncompressBL) ){
            cout<<endl<<"error build_uncompressbl_secuCheck() !buildTransacInVector"<<endl;
            exit_call();
            return UncompressBL;
        }
        
        if(!PrimerChange(bl2[primerInit], primerInit)){
            cout<<endl<<"error build_uncompressbl_secuCheck() !PrimerChange(bltype, primerInit)"<<endl;
            exit_call();
            return UncompressBL;
        }

    }

    cout<<endl<<"debug build_uncompressbl_secuCheck loop ENDED"<<endl;

    addHexStringInVector(UncompressBL, "9696");

    for(uint i = 0; i < UncompressBL.size();i++){
        cout<<byteToHex2(UncompressBL[i]);
    }
    cout<<endl<<endl;
    if(primerInit+32 > bl2.size()-1){
        cout<<endl<<"error build_uncompressbl_secuCheck() primerInit+32 > bl2.size()"<<endl;
        exit_call();
        return UncompressBL;
    }

    for (int i =0; i< bl2.size(); i++){
        cout<<byteToHex2(bl2[i]);
    }

    HashUncompressBL = read_blRefactHash(bl2);

    if(sha3_256v(UncompressBL) != HashUncompressBL){
        cout<<endl<<"error build_uncompressbl_secuCheck() sha3_256v(UncompressBL) != read_blRefactHash(bl2)"<<endl;
        cout<<endl<<"UncompressBL: ";
        for(uint8_t i =0; i<32;i++){
            cout<<byteToHex2(UncompressBL[i]);
        }
        cout<<endl<<"HashUncompressBL: ";
        for(uint8_t i =0; i<32;i++){
            cout<<byteToHex2(HashUncompressBL[i]);
        }
        exit_call();
        return UncompressBL;
    }

    for(uint8_t i=0; i<32; i++){
        UncompressBL.push_back(HashUncompressBL[i]);
    }

    return UncompressBL;

}











#endif


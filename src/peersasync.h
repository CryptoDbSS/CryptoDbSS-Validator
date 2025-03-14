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

#ifndef PEERSASYNC_H
#define PEERSASYNC_H


#include <random>
#include <future>
#include "curlpostAsync.h"
#include <chrono>
#include "CryptoDbSS.cpp"

using namespace std;
using namespace chrono;

extern map< array <unsigned char,64>, dbstruct >mapIndex;
extern bool matchminRounInit;
extern bool postRefactRoundInit;
extern mutex peerssyncblock;
extern vector<string> peersMatchMin;
extern string ShaLBBBuffered;
extern string publicDirNode;
extern uint64_t timingbl;
extern uint64_t lastbl;
extern mutex WritingAccSync;
extern map<string,nodeStruct> Nodes; 
extern  string matchminProposalArrengelStr;
extern bool matchminbuilt;
extern bool shaMatchMinproposalReveled;
extern map<string ,string> matchminSortRound;
extern string shaMatchMinproposal;
extern string matchminsorted;
extern mutex peersMatchMinBlockmtx;
extern uint16_t errorMatchminCount;

int maxblks();
void exit_call();
string vectorstring(vector<unsigned char> &vec);
string timing();
string SHAstg(string stg);
string shaLBB();
void addStringInVector(vector<string> &vec, string datatocodify);
void addHexStringInVector(vector<uint8_t> &vec, string datatocodify);
unsigned long long lastblockbuilt();
string blread(string bl);
string searchlastmove(string acctpubk,bool IsAccSync);
vector<uint8_t> stringToBytes(const std::string& str);
string bytesToString(const std::vector<uint8_t>& bytes);
vector<uint8_t> readFile(const std::string& filename);
bool clearblksOps();
void blockThread(bool &threadbool , string threadName, uint sleepfor);
string LocalSigner(string data);

bool Loggednode(string ip){

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    auto it = Nodes.begin();
    while (it != Nodes.end()) {
        //cout<<endl<<" Loggednode iter "<<it->second.ip<< " ip request "<< ip<<endl;
        if (ip == it->second.ip.substr(0 , ip.length())){
            if(it->second.logged){
                return true;
            } else {
                return false;
            }
        }
        ++it;
    }
    return false;
}

string random32Hex(){
        extern mutex randommtx;
        std::unique_lock<std::mutex> randommtxlock(randommtx);
        string random32hexstr="";
    for (int i =0; i<32; i++){
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(0, 255);
        random32hexstr += unsignedCharToHex(dist(gen));
    }
    randommtxlock.unlock();
    return SHAstg(random32hexstr);
}

bool loginPeer(string dataAccount, string ip){

    Nodes[dataAccount.substr(0, 130)].ip=ip+":18090";
    Nodes[dataAccount.substr(0, 130)].logged=true;
    Nodes[dataAccount.substr(0, 130)].LoggedDataKey=SHAstg(dataAccount.substr(0, 130));

    return true;
}

bool LoadPeersInit(){

    for (const auto &entry : std::filesystem::directory_iterator("peer/PublicNode/")){
        if (entry.is_regular_file()){
            string PublicNode = entry.path().filename().string();
            for (auto &acc : PublicNode) {acc = std::toupper(acc); }
            Nodes[PublicNode].LoggedDataKey=SHAstg(PublicNode);
            Nodes[PublicNode].ip="unavailable";        
            }
    }
    return true;
}

bool peersLogin(){

    string linea;
    vector<string> filalocal;
    vector<string> datoslocal;

    LoadPeersInit();

    for (const auto &entry : std::filesystem::directory_iterator("peer/")){
        if (entry.is_regular_file()){
            string NodeIp = entry.path().filename().string();
            ifstream archivo(entry.path());
            if (archivo.is_open()){
                vector<string> fila;
                vector<string> datos;
                getline(archivo, linea);
                archivo.close();

                for (const auto &entry : std::filesystem::directory_iterator("peer/PublicNode/")){

                    if (entry.is_regular_file()){

                        string PublicNode = entry.path().filename().string();
                        for (auto &acc : PublicNode) {acc = std::toupper(acc); }
                        if(SHAstg(PublicNode)==linea.substr(0,64)){

                            ifstream archivo(entry.path());
                            if (archivo.is_open()){

                                archivo.close();

                                ifstream NodeDirDb("peer/PublicNode/"+entry.path().filename().string());

                                if (!NodeDirDb.is_open()){
                                    cout << "invalid login data ";
                                    continue;
                                }
                                // comprobar cert con cuenta local
                                NodeDirDb.close();
                                if (linea.substr(66, 64)!=SHAstg(publicDirNode)){ cout << "invalid login data ";
                                    continue;
                                }
                                
                                if (!verifySignature(linea.substr(0, 208), linea.substr(210, 128), loadPublicKey(PublicNode.substr(2, 128)))){cout << "invalid login sign" ;
                                    continue;
                                }

                                string lbbSHA = shaLBB();
                                string timer = timing();

                                linea=SHAstg(publicDirNode)+"00"+linea.substr(0, 64)+"00"+lbbSHA+"00"+timer;
                                
                                string signer = LocalSigner(linea);
                                linea=linea+"00"+signer;

                                verifySignature(linea.substr(0, 208), signer, loadPublicKey(PublicNode.substr(2, 128)));

                                string response_data = curlpost2("https://" + NodeIp + "/pair", linea, 1000);

                                if (response_data.length() != linea.length()
                                ||response_data.substr(0,64)!=linea.substr(66,64)
                                ||response_data.substr(66,64)!=SHAstg(publicDirNode)
                                ||response_data.substr(132,64) != lbbSHA
                                ||response_data.substr(198,10) != timer
                                )                                                   {
                                    cout << " bad_response from node";
                                    //continue;
                                }

                                cout << endl<< "node login: " << response_data;

                                Nodes[PublicNode].logged=true;
                                Nodes[PublicNode].ip=NodeIp;
                                Nodes[PublicNode].LoggedDataKey=SHAstg(PublicNode);

                            }
                        }
                    }
                }
            }
        }
    }

    ifstream archivo2("node/priv");
    if (archivo2.is_open()){
        string pr;
        filalocal.push_back("localhost");
        getline(archivo2, pr);
        archivo2.close();
        string publiclocal = derivate(pr);
        pr="";

        Nodes[publiclocal].logged = true;
        Nodes[publiclocal].ip="localhost";
        Nodes[publiclocal].LoggedDataKey=SHAstg(publiclocal);

    } else {
        cout << endl<< endl<< " node pk not set" << endl<< endl;
        exit_call();
    }


    return true;
}

int MaxFromNetwork(vector<unsigned long long> lastblvd){
    unsigned long long c = 0;
    for (int i = 0; i < lastblvd.size(); i++){
        if (lastblvd[i] > c){
            c = lastblvd[i];
        }
    }
    return c;
}

int MatchMaxIntValue(const map<int, int> &contadorDeRepeteiciones){
    // Crear un vector de pares (numero, repeticiones) a partir del mapa
    std::vector<std::pair<int, int>> pares(contadorDeRepeteiciones.begin(), contadorDeRepeteiciones.end());

    // Ordenar el vector por valor descendente
    std::sort(pares.begin(), pares.end(), [](const std::pair<int, int> &a, const std::pair<int, int> &b) { 
        return a.second > b.second; });

    // Encontrar el número con mayor registro de repeticiones
    int max_repeticiones = 0;
    int numero_con_mas_repeticiones = 0;
    for (auto par : pares) {
        if (par.second > max_repeticiones){
            max_repeticiones = par.second;
            numero_con_mas_repeticiones = par.first;
        }
    }

    return numero_con_mas_repeticiones;
}

std::string MatchMaxIntValue2(const std::vector<uint64_t>& lastblvd) {
    std::map<uint64_t, uint> contadorDeRepeticiones;
    for (uint64_t valor : lastblvd) {
        contadorDeRepeticiones[valor]++;
    }

    std::vector<std::pair<uint64_t, uint>> pares(contadorDeRepeticiones.begin(), contadorDeRepeticiones.end());
    std::sort(pares.begin(), pares.end(), [](const std::pair<uint64_t, int>& a, const std::pair<uint64_t, int>& b) { return a.second > b.second; });

    uint64_t max_repeticiones = 0;
    uint64_t numero_con_mas_repeticiones = 0;
    for (const auto& par : pares) {
        if (par.second >= max_repeticiones && par.first >= numero_con_mas_repeticiones) {
            max_repeticiones = par.second;
            numero_con_mas_repeticiones = par.first;
        }
    }

    std::string numbercount = uintToHex(max_repeticiones);
    std::string number = uintToHex(numero_con_mas_repeticiones);
    return number + numbercount;
}

std::string MatchMaxStringValue(const std::map<std::string, int>& contadorDeRepeticiones) {

    std::vector<std::pair<std::string, int>> pares(contadorDeRepeticiones.begin(), contadorDeRepeticiones.end());

    // Ordenar el vector por valor descendente
    std::sort(pares.begin(), pares.end(), [](const std::pair<std::string, int>& a, const std::pair<std::string, int>& b) {
        return a.second > b.second;
    });

    int max_repeticiones = 0;
    std::string cadena_con_mas_repeticiones;
    for (const auto& par : pares) {
        if (par.second > max_repeticiones) {
            max_repeticiones = par.second;
            cadena_con_mas_repeticiones = par.first;
        }
    }

    return intToHex(max_repeticiones)+cadena_con_mas_repeticiones;
}

std::string MatchMaxString(const std::vector<std::string>& strings) {
    std::map<std::string, int> contadorDeRepeticiones;
    for (const std::string& str : strings) {
        contadorDeRepeticiones[str]++;
    }
    return MatchMaxStringValue(contadorDeRepeticiones);
}

int matchMaxAvg(vector<unsigned long long> lastblvd){
    map<int, int> iterations_counter;
    for (int value : lastblvd){
        iterations_counter[value]++;
       // cout << endl<< "value : " << valor << endl;
       // cout << endl<< "iterations_counter[value]++: " << iterations_counter[value] << endl;
    }
    int mathMaxAVG = MatchMaxIntValue(iterations_counter);
   // cout << endl<< "matchMaxAvg: " << mathMaxAVG << endl;
    return mathMaxAVG;
}

string matchMinQueue(){

    std::unique_lock<std::mutex> peersMatchMinBlockmtxlock(peersMatchMinBlockmtx);
    if (peersMatchMin.size()>0){
        return peersMatchMin[0];
    }
    return "Null";
}

string matchMinQueueIp(){

    std::unique_lock<std::mutex> peersMatchMinBlockmtxlock(peersMatchMinBlockmtx);
    if (peersMatchMin.size()>0){
        auto iter  = Nodes.find(peersMatchMin[0]);
        if (iter != Nodes.end()){
            return iter->second.ip;
        }
    }
    return "Null";
}

void matchmingMistake(){

    errorMatchminCount++;

    if(errorMatchminCount>20){

        cout<<endl<<" matchmingMistake max attemp"<<endl<<"skipping matchmin node";

        if(peersMatchMin.size()>0){
            peersMatchMin.erase(peersMatchMin.begin() + 0);
            errorMatchminCount = 0;
        }
        if(peersMatchMin.size() < 1 ){
            peersMatchMin.clear();
            matchminRounInit = false;
        }
        postRefactRoundInit = false;

        ClearOpBlks();

    }

return;

}

bool lastbllocalmatchsync(){

    extern string ShaLBBBuffered;
    string ipquery = matchMinQueueIp();

    if (ipquery=="localhost"){
        return true;
    }

    string datasign = ullToHex(lastbl)+shaLBB()+timing();
     // cout<<endl<<"debug lastbllocalmatchsync() datasign.length() "<<datasign.length()<<endl;

    string lblocal = ullToHex(lastbl);
    string sign = LocalSigner(datasign);
    string jsonval = "{\"x1\": \"" + datasign + "\", \"x2\": \"" + sign+ "\"}"; 
    string response;
    for(int i =0 ; i<3 ;i++){
        response = curlpost2("https://" + ipquery + "/lastblsync", jsonval, 1000);
        cout<<endl<<"lastbllocalmatchsync  response "+ipquery+" "<<response;
 
        if (response == "STATUS_OK"){
            cout<<endl<<"lastbllocalmatchsync STATUS_OK";
            errorMatchminCount = 0;
            return true;
        }
        matchmingMistake();
    }
    
    return false;

}

string lastblDW(){

    vector<uint64_t> lastblc;
    int timeout_ms = 1000;
    string random32hexstr=random32Hex();

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    auto Nodes2 = Nodes;
    peerssyncblocklock.unlock();

    auto it = Nodes2.begin();
    while (it != Nodes2.end()) {

        string peerIp = it->second.ip;

        if (peerIp.substr(0, 9) == "localhost"||peerIp == "unavailable") {
            ++it;
            continue;
        }
        string datastring =curlpost2( "https://"+peerIp+"/lastBlLocal", random32hexstr, timeout_ms);
        if (datastring.length() != 144 || !HexCheck(datastring)){
            cout << endl<<" lastblDW() : node " +peerIp + ": Response Fail. Invalid data "+datastring;
            ++it;
            continue;
        }
        if( !verifySignature(random32hexstr+datastring.substr(0,16), datastring.substr(16,128) ,  loadPublicKey(it->first.substr(2 ,128))) ){
            cout<<endl<< "Invalid sign from request : https://"+peerIp+"/lastBlLocal";
            ++it;
            continue;
        }

        it->second.lastblLocal = hexToULL(datastring.substr(0,16));
        lastblc.push_back(hexToULL(datastring.substr(0,16)));
        ++it;
    }

    lastblc.push_back(lastbl);
    string result = MatchMaxIntValue2(lastblc);

    return MatchMaxIntValue2(lastblc);
}

vector<unsigned char> blRefactHashedQueryNode(string peerIpAddress){
    string response = curlpost2("https://"+peerIpAddress+"/peersMatchMin", "blRefactHash", 1000);
    cout<<endl<<" blRefactHashedQueryNode() "<<peerIpAddress<<" response "<<response;
    return stringToBytes(response);
}

bool matchMinBuildQueueFromNetwork(){

    std::unique_lock<std::mutex> peersMatchMinBlockmtxlock(peersMatchMinBlockmtx);
    peersMatchMin.clear();
    peersMatchMinBlockmtxlock.unlock();

    vector<string> shaqueue;
    int timeout_ms = 1000;
    uint timingcount =0;
    std::map<std::string, std::vector<std::string>> map;

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    auto Nodes2 = Nodes;
    peerssyncblocklock.unlock();

    auto it = Nodes2.begin();
    while (it != Nodes2.end()) {

        string PeerIp = it->second.ip;

        if(PeerIp=="localhost"||PeerIp=="unavailable"){
            ++it;
            continue;
        }

        string response = curlpost2("https://"+PeerIp+"/peersMatchMin", "SHA", timeout_ms);

        try {

            if (response == "00"){
                cout << endl<< it->second.ip+"/peersMatchMin SHA" << ": Response Fail. ";
                ++it;
                continue;
            }

            auto x = crow::json::load(response);

            string datastring = x[0].s();
            string shalb = x[1].s();
            string timingblshaminround = x[2].s();
            string firmnode = x[3].s();

            if(!verifySignature(datastring+shalb+timingblshaminround, firmnode ,  loadPublicKey(it->first.substr(2 , 128)))){
                cout<<endl<<"invalid sign from "<<it->first<< " response from: "<< "https://"+PeerIp+"/peersMatchMin SHA";
                ++it;
                continue;
                        
            }

            map[datastring].push_back(PeerIp);
            shaqueue.push_back(datastring);
            timingcount+=hexToUint(timingblshaminround);

        }     
        catch (const std::exception& e) {
                cout<<endl<<" matchMinBuildQueueFromNetwork() invalid response from: "<< "https://"+PeerIp+"/peersMatchMin SHA "+response;

        }
        ++it;
    }


    string maxsha = MatchMaxString(shaqueue);


    if( (hexToInt(maxsha.substr(0,8))*10000) / (Nodes2.size()-1<5100) ){
        cout<<endl<<"matchMinBuildQueueFromNetwork maxsha fail result: "<<(hexToInt(maxsha.substr(0,8))*10000) / (Nodes2.size()-1<5100)<<"%" ;
        return false;
    }

    maxsha = maxsha.substr(8 , 64);

    for (const std::string& pairs : map[maxsha]) {

        //cout<<endl<<"built matchmin network Dir: request to "<<pairs;
        string datastring = curlpost2("https://"+pairs+"/peersMatchMin", "Dir", timeout_ms);

        try {
            auto x = crow::json::load(datastring);
            vector<string> peersDir;
            string jsonstring;
            string peersstring="";
            for(int i = 0; i<x.size();i++){
                jsonstring = x[i].s();
                if(jsonstring.length()!= 130 ){ 
                    cout<<endl<<"jsonstring.length()!= 130 "<<jsonstring; 
                    continue;
                }
                peersDir.push_back(jsonstring);
                peersstring+=jsonstring;
            }

            if (SHAstg(peersstring) == maxsha){

                peersMatchMinBlockmtxlock.lock();
                
                for(int i=0; i<peersDir.size(); i++){
                    peersMatchMin.push_back(peersDir[i]);
                }   
                timingbl = timingcount/shaqueue.size();
                return true;
            }
            peersDir.clear();
        }
        catch (const std::exception& e) {
            cout<<endl<<"invalid response from: "<< "https://"+pairs+"/peersMatchMin Dir";
            continue;
        }
    }
    return false;       
}

string matchMin(string  &ShaLBBBuffered){

    vector<uint8_t> shalb;
    addHexStringInVector(shalb, shaLBB());
    string minPairIP = "";
    string minPairSHA = "";
    string minPairDIR = "";
    uint16_t intmin = 256;
    uint8_t round = 0;
    uint8_t roundMin = 0;
    uint8_t sums = 0;
    string x;
    uint8_t elementssums[32];

    for(uint8_t i = 0; i<32 ; i++ ){
        elementssums[i]=255;
    }

    auto it = Nodes.begin();
    while (it != Nodes.end()) {

        round = 0;
        vector<uint8_t> nodeAddress;
        addHexStringInVector(nodeAddress, SHAstg(it->first) );

        for (uint8_t i = 0; i<32; i++){

            sums = 0;
            if (nodeAddress[i] > shalb[i]) {
                sums = nodeAddress[i] - shalb[i];
            }
            if ( nodeAddress[i] < shalb[i] ) {
                uint8_t sums2 = nodeAddress[i];
                while(sums2 != shalb[i]){
                    sums++;
                    sums2--;
                }
            }

            if( sums < elementssums[i]  ){
                minPairIP = it->second.ip;
                minPairSHA = it->first;
                minPairDIR = it->first;
                break;
            } else {
                if (sums > elementssums[i]){
                    break;
                }
            }
        }
        ++it;
    }

    return minPairDIR;
}

string matchMin2(string  &ShaLBBBuffered, vector<string> &elementsstr){

    vector<uint8_t> shalb;
    addHexStringInVector(shalb, shaLBB());
    string minPairIP = "";
    string minPairSHA = "";
    string minPairDIR = "";
    uint8_t round = 0;
    uint8_t roundMin = 0;
    uint8_t sums = 0;
    string x;
    uint16_t elementssums[32];

    for(uint8_t i = 0; i<32 ; i++ ){
        elementssums[i]=256;
    }

    for(uint i = 0; i < elementsstr.size(); i++){ 

        round = 0;
        vector<uint8_t> nodeAddress;
        addHexStringInVector(nodeAddress, SHAstg(elementsstr[i]) );

        for (uint8_t i = 0; i<32; i++){

            sums = 0;
            if (nodeAddress[i] > shalb[i]) {
                sums = nodeAddress[i] - shalb[i];
            }
            if ( nodeAddress[i] < shalb[i] ) {
                uint8_t sums2 = nodeAddress[i];
                while(sums2 != shalb[i]){
                    sums++;
                    sums2--;
                }
            }

            if( sums < elementssums[i]  ){

                minPairDIR = elementsstr[i];
                break;
            } else {
                if (sums > elementssums[i]){
                    break;
                }
            }
        }

    }

    return minPairDIR;
}

vector<string> PublicNodesDir(){
    const std::string path = "peer/PublicNode/";
    vector<string> fileNames;
    for (const auto &entry : std::filesystem::directory_iterator(path)){
        if (entry.is_regular_file()){
            ifstream archivo(entry.path());
            if (archivo.is_open()){
                fileNames.push_back(entry.path().filename().string());
            }
            archivo.close();
        }
        
    }
    return fileNames;
}

vector<string> PublicNodesDir2(){
    const std::string path = "peer/PublicNode/";
    vector<string> fl;
    fl.push_back("0");
    fl.push_back("Public Address");
    fl.push_back("IP");
    fl.push_back("connect");
    for (const auto &entry : std::filesystem::directory_iterator(path)){
        if (entry.is_regular_file()){
            ifstream archivo(entry.path());
            if (archivo.is_open()){
                fl.push_back("0");
                fl.push_back(entry.path().filename().string());
                fl.push_back( Nodes[entry.path().filename().string()].ip );
                fl.push_back( to_string(Nodes[entry.path().filename().string()].logged) );
            }
            archivo.close();
        }
        
    }
    return fl;
}

string randomPeer(){

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, Nodes.size() );
    uint random_index = dist(gen);

    auto it = Nodes.begin();
    for(uint i = 0; i<random_index;i++){
        ++it;
    }

    string random_string = it->first;
    peerssyncblocklock.unlock();
    cout << endl<< "random Peer: " <<uintToHex(random_index)<<" "+ random_string ;
    return random_string;
}

string randomPeerIp(){

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, Nodes.size() - 1);
    int random_index = dist(gen);

    auto it = Nodes.begin();
    for(uint i = 0; i<random_index;i++){
        ++it;
    }

    string random_string = it->second.ip;
    peerssyncblocklock.unlock();
    cout << endl<< "random Peer: " <<uintToHex(random_index)<<" "+ random_string;
    return random_string;
}

string ipDir(string ip){

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    string dirIp="Null";

    auto it = Nodes.begin();
    while (it != Nodes.end()) {
        if(it->second.ip.substr(0,ip.length())==ip){
            dirIp=it->first;
            break;
        }
        ++it;
    }
    return dirIp;
}

string ShaOfBlNetwork(uint64_t BlNumbr){

    string  Sx1 = uintToHex(0);
    string  Sx2 = uint64ToHex(BlNumbr);
    string  Sx3 = random32Hex();
    string jsonval = "{\"x1\": \"" + Sx1 + "\", \"x2\": \"" + Sx2 + "\", \"x3\": \"" + Sx3 + "\"}"; 

    vector<string> nodeShaReq;

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    auto Nodes2 = Nodes;
    peerssyncblocklock.unlock();

    auto it = Nodes2.begin();
    while (it != Nodes2.end()) {

        string peerIp = it->second.ip;

        if (peerIp.substr(0, 9) == "localhost"||peerIp == "unavailable") {
            ++it;
            continue;
        }

        string datastring = curlpost2( "https://"+peerIp+"/blockdl", jsonval, 4000);

        try {
            auto x = crow::json::load(datastring);
            string str1 = x[0].s();
            string str2 = x[1].s();
            
            if (str1.length() != 128 || !HexCheck(str1) || str1.length() != 128 || !HexCheck(str2) ){
                cout << endl<< peerIp << ": Response Fail. Invalid data";
                ++it;
                continue;
            }

            if( !verifySignature( str1.substr(0,64)+Sx3 , str2 ,  loadPublicKey( it->first.substr(2 , 128))) ){
                cout<<endl<< "Invalid firm from request : https://"+peerIp+"/blockdl";
                ++it;
                continue;
            }


            nodeShaReq.push_back(str1.substr(0,64));

        }catch (const std::exception& e) {
            cout<<endl<<"ShaOfBlNetwork error response  ";
        }
        ++it;
    }


    if(nodeShaReq.size()>0){

        string maxsha = MatchMaxString(nodeShaReq);

        if( (hexToInt(maxsha.substr(0,8))*10000 )/ (Nodes2.size()-1) >= 5000 ){

            cout<<endl<<"  ShaOfBlNetwork OK result: "<<(hexToInt(maxsha.substr(0,8))*10000 )/ (Nodes2.size()-1) <<"%";

            return maxsha.substr(8, 64);
        }

        cout<<endl<<"  ShaOfBlNetwork fail result: "<<(hexToInt(maxsha.substr(0,8))*10000 )/ (Nodes2.size()-1) <<"%";

    }

    return "error request ShaOfBlNetwork";

}

string dlBl(uint64_t BlNumbr, string &NodePeerIP){

    cout<<endl<<"dlbl from "<<NodePeerIP;

    string random32hexstr = random32Hex();
    string  Sx1 = uint8ToHex(1);
    string  Sx2 = uint64ToHex(BlNumbr);
    string  Sx3 = random32hexstr;
    string blockdl = curlpost2("https://" + NodePeerIP + "/blockdl", "{\"x1\": \"" + Sx1 + "\", \"x2\": \"" + Sx2 + "\", \"x3\": \"" + Sx3 + "\"}", 4000);

    if (blockdl == "00"){
        cout << endl<< "getblock timeout ";
    }

    try {                                                                                                                                                                                                                         

        auto x = crow::json::load(blockdl);
        string block = x[0].s();
        string signature = x[1].s();
        
        cout << endl<< "dlbl bl download  "<<blockdl<<endl;

        if (block.length() < 426 || !HexCheck(block) || signature.length() != 128 || !HexCheck(signature) ){
            cout << endl<< NodePeerIP << ": Response Fail. Invalid data";
            return "error downlaoding bl - wrong format";
        }
        if( !verifySignature( block.substr(0,block.length()-64)+Sx3 , signature ,  loadPublicKey( ipDir(NodePeerIP).substr(2 , 128))) ){
            cout<<endl<< "Invalid firm from request : https://"+NodePeerIP+"/blockdl";
            return "error downlaoding bl - invalid signature";
        }

        return block.substr(0,block.length()-64);


    }catch (const std::exception& e) {
        cout<<endl<<"ShaOfBlNetwork error response : "<<blockdl;
    }

    return "error downlaoding bl";

}

string blnetworkIndex(uint8_t DataType, uint64_t BlNumbr){

    if(DataType == 0 ){
        string result = ShaOfBlNetwork(BlNumbr);
        if(result.length() == 64 && HexCheck(result) ){
            return result;
        }
    }

    if(DataType == 1 ){

        string result = ShaOfBlNetwork(BlNumbr);

        cout<<endl<<" ShaOfBlNetwork "<<BlNumbr<<" : "<<result;

        if(result.length() == 64 && HexCheck(result) ){
            for ( int tries  = 5 ; tries > 0 ; tries-- ){
                
                string peerip = randomPeerIp();
                if(peerip == "unavailable" || peerip == "localhost" ){
                    break;
                }
                string blDl = dlBl(BlNumbr, peerip);
                vector<unsigned char> vecdebug;
                addHexStringInVector(vecdebug, blDl);

                vector<unsigned char> vecdebughash =sha3_256v(vecdebug) ;
                string bldlhashed = vectorstring (vecdebughash);

                 cout<<"blnetworkIndex  bldlhashed "<< bldlhashed;

                if (bldlhashed == result){
                    return blDl;
                }

            }
        }
    }

    return "res wrong ";

}

bool getblock( string lbi){

    extern const uint16_t maxblksize;
    extern map<int, string> shablbbuffer;
    extern string LBBBuffered;
    extern string ShaLBBBuffered;
    extern vector<vector<string>> peersObj;
    vector<string> accA;
    vector<string> accB;
    uint8_t bltype;
    int timeout_ms = 8000;
    vector<unsigned char> bl2;

    //get download block from a Node from network
    string blockdl = blnetworkIndex(1 , stoull(lbi));

    cout<<endl<<"getblock blockdl "<< blockdl<<endl;

    if (blockdl.length() < 426){
        cout << endl<< "getblock error | content : "+blockdl<<endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
        return false;
    }

    addHexStringInVector(bl2, blockdl);

    ofstream filew("blocks/dlsync/" + to_string( lastbl+1 ) , ios::binary | ios::out);
    if (!filew) { return "error writing bl dl"; }
    for (unsigned int i = 0; i < bl2.size(); i++){
        filew.seekp(i);
        filew.put(bl2[i]);
    }

    filew.close();

    filew.open("blocks/" + to_string( lastbl+1 ) , ios::binary | ios::out);
    if (!filew) { return "error writing bl dl"; }
    for (unsigned int i = 0; i < bl2.size(); i++){
        filew.seekp(i);
        filew.put(bl2[i]);
    }
    filew.close();

    build_uncompressbl_secuCheck(lastbl+1);

    lastbl++;

    for (const auto &entry : std::filesystem::directory_iterator("blocks/dlsync")){if (entry.is_regular_file()){remove(entry);}}

    ClearOpBlks();

    LBBBuffered = blreadblock(to_string(lastbl));
    ShaLBBBuffered=shaLBB();

    return true;
}

bool sync( unsigned long long &lblbc){

    lblbc = hexToULL(lastblDW().substr(0,8));

    getblock(to_string(lastbl+1));
    if (lastbl < lblbc){
        getblock(to_string(lastbl+1));
    }

    if (lastbl < lblbc){
        sync(lblbc);
    }

    return true;
}

vector<string> PublicNodesDirMulti(){
    const std::string path = "peer/PublicNode/";
    vector<string> fileNames;
    for (const auto &entry : std::filesystem::directory_iterator(path)){
        if (entry.is_regular_file()){
            ifstream archivo(entry.path());
            if (archivo.is_open()) {
                fileNames.push_back(entry.path().filename().string());
            }
            archivo.close();
        }
        
    }
    return fileNames;
}

bool queueErased(){

    string ipquery = matchMinQueueIp();

    for(int tries = 0; tries < 3;tries++){

        string response_data = curlpost2("https://"+  ipquery + "/queueErased", "null", 1000);
        if (response_data == "00") {
            cerr << "Req Status 0" << endl;
            continue;
        }
        if(response_data == ":)" ){
                
            return false;
        } else{ 
            
            return true;
        }
        
    }

return true;
}   

void matchMinBuildQueue(){

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    auto Nodes2 = Nodes;
    peerssyncblocklock.unlock();

    std::unique_lock<std::mutex> peersMatchMinBlockmtxlock(peersMatchMinBlockmtx);
    peersMatchMin.clear();
    vector<string>collectdata;
    string shavalue = shaLBB(); 

    auto it = Nodes2.begin();
    while (it != Nodes2.end()){

        collectdata.push_back(it->first);
        ++it;

    }

    for(uint i = 0;i < Nodes2.size(); i++ ){

        string matchminresult = matchMin2( shavalue , collectdata);
        shavalue += matchminresult;
       // cout<<endl<<"matchMinBuildQueue buil N "<<i<<" ; "<<matchminresult;
        peersMatchMin.push_back(  matchminresult);

        for (uint e = 0; 0<collectdata.size(); e++){
            if(collectdata[e] == matchminresult ){
                collectdata.erase(collectdata.begin() + e);
                break;
            }
        }
    }
    return  ;
}

void syncNetwork(){
    //last block network
    extern vector<vector<string>> peersObj;
    extern unsigned long long lastblDWULL;
    extern bool synced;
    extern bool syncing;
    extern bool Refactorizing;
    string hexlblbc = lastblDW();
    unsigned long long lblbc = hexToInt(hexlblbc.substr(0,8));
    unsigned long long lbi = lastbl;

    int fiftyone =  (hexToInt(hexlblbc.substr(8,8))*10000)/Nodes.size();

    // cout<<endl<<"syncNetwork() debug fiftyone "<<fiftyone;

    if(fiftyone> 5100 ){
        lastblDWULL = hexToULL(hexlblbc.substr(0,8));
    } 
    
/*
    if(lbi==lblbc&& fiftyone> 5100 &&matchMinQueueIp()!= "localhost"){
        blksOPSyncQueue.clear();
    }
*/
    if (  (  lbi+1==lblbc  || lbi+1 < lblbc) && !Refactorizing &&!matchminRounInit&&!postRefactRoundInit){
        if((  lbi+1==lblbc&&queueErased()  || lbi+1 < lblbc) && !Refactorizing&&!matchminRounInit&&!postRefactRoundInit){

            synced = false;
       
            extern bool comfirmOptrancasyncRun;
            extern bool syncqueue;
            extern mutex writingspace;
            extern bool statusCheckRun;

            matchminRounInit = false;
            cout << endl<< "Syncyng to last block";

            ClearOpBlks();

            std::unique_lock<std::mutex> WritingAccSynclock(WritingAccSync); 

            mapIndex.clear();

            WritingAccSynclock.unlock();

            if( lbi+1 < lblbc){
                extern bool BlAntIsMatch;
                extern int lastmatchsyncqueue;
                extern vector<string>blksOPSyncQueue;
                extern mutex blkQueuemtx;

                std::unique_lock<std::mutex> peersMatchMinBlockmtxlock(peersMatchMinBlockmtx);

                peersMatchMin.clear();

                peersMatchMinBlockmtxlock.unlock();
                std::unique_lock<std::mutex> blkQueuemtxlock(blkQueuemtx);

                blksOPSyncQueue.clear();
                lastmatchsyncqueue = 0;
                BlAntIsMatch = false;

                blkQueuemtxlock.unlock();

            }

            sync( lblbc);

            lblbc = hexToULL(lastblDW().substr(0,8));

            if(lblbc == lastbl){
                synced = true;
            } else {
                syncNetwork();
            }

            extern vector<unsigned char> blRefactHashed;
            
            string lastblvar = to_string(lastbl);
            vector<unsigned char> bl2;
            blread2(lastblvar, bl2);
            blRefactHashed=read_blRefactHash(bl2);

        }
    }
    
    synced = true;
    syncing = false;
}

bool itsAlive(string Publicnode, string &ShaLBBBuffered){

    int timeout_ms = 2000;
    string linea;
    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    auto Nodes2 = Nodes;
    peerssyncblocklock.unlock();

    ifstream archivo("peer/" + Nodes2[Publicnode].ip);
    if (archivo.is_open()){

        getline(archivo, linea);
        archivo.close();
        string random32hexstr = random32Hex();
        string msg = publicDirNode+"00"+Publicnode+"00"+random32hexstr+"00"+timing();
        for (auto &s : msg){s = toupper(s);}
        string sign = LocalSigner(msg);
        msg = msg+"00"+sign;

        for(int i = 2 ; i >0 ; i--){
            
            string response = curlpost2("https://"+Nodes2[Publicnode].ip + "/ItsAlive", msg, timeout_ms);

            if (response == "00") {
                cerr << "Req Status 0" << endl;
                continue;
            }
            
            for (auto &s : Publicnode){s = toupper(s);}

            if (response.substr(0, 130) != Publicnode){
                cout << "Req Status: bad_response: No de recibio la data esperada  response_data.substr(0, 130) " <<response.substr(0, 130)<< " Publicnode "<<Publicnode;
                return false;
            }
            if (response.substr(132, 130) != publicDirNode){
                cout << "Req Status: bad_response: No de recibio la data esperada  response_data.substr(132, 130) " <<response.substr(132, 130)<< " publicDirNode "<<publicDirNode;
                return false;
            }
            if(stoi(response.substr(330, 10))>stoi(timing())+300 || stoi(response.substr(330,10))<stoi(timing())-300){
                cout << "Req Status: bad_response: Timing cert error";
                return false;
            }

            //verificar validez del timing
            if (verifySignature(Publicnode+"00"+publicDirNode+"00"+random32hexstr+"00"+response.substr(330,10), response.substr(342, 128), loadPublicKey(Publicnode.substr(2, 128)))){

                return true;
            }
            // verificar firma del response y status
            cout<<endl<<"wrong signature alive connection";
            return false;
        }
     
        
    } else{
        cout<<endl<<"itsAlive debug !file.open() "<<Nodes2[Publicnode].ip;
         
    }

    return false;
}

void reAlive(int timeout_ms){

   // cout<<endl<<"======== > ReAlive init"<<endl;

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    auto Nodes2 = Nodes;
    peerssyncblocklock.unlock();

    auto it = Nodes2.begin();
    while (it != Nodes2.end()) {

        if (it->second.ip == "unavailable" && it->first!=publicDirNode){
            string NodeDir = it->first;
            for (const auto &entry2 : std::filesystem::directory_iterator("peer")){
                
                if (entry2.is_regular_file()){

                    string Nodeip = entry2.path().filename().string();
                    ifstream archivo2(entry2.path());
                    if (archivo2.is_open()){
                        string linea;
                        getline(archivo2, linea);
                        archivo2.close();

                        if(SHAstg(NodeDir)==linea.substr(0 , 64)){

                            //TIMING
                            string localtimestg = timing();
                            string LastBlSHA = shaLBB();
                            string msg = SHAstg(publicDirNode)+"00"+SHAstg(NodeDir)+"00"+LastBlSHA+"00"+localtimestg;
                            // cout<<endl<<"debug msg length"<<msg.length()<<endl;
                            // cout<<endl<<"debug msg : "<<msg<<endl;
                               
                            string sig = LocalSigner(msg);

                            msg = msg + "00" + sig;
                            //cout<<endl<<"debug msg length"<<msg.length()<<endl;
                            if (!verifySignature(msg.substr(0, 208), sig, loadPublicKey(publicDirNode.substr(2, 128)))){
                                cout<<endl<<"signin error"<<endl;
                                break;
                            }
                            string stresponse = curlpost2("https://"+Nodeip + "/pair", msg, timeout_ms);
                            if (stresponse == "00") {
                                cerr << "Req Status 0" << endl;
                                break;
                            }

                            //cout << "response from: https://"+ Nodeip + "/pair "<< stresponse << endl;
                            if(stresponse.length()!=338){
                                break;
                            }
                            
                            if (!verifySignature(SHAstg(NodeDir)+"00"+SHAstg(publicDirNode)+"00"+LastBlSHA+"00"+localtimestg, stresponse.substr(210, 128), loadPublicKey(NodeDir.substr(2, 128)))){
                                cout << "Invalid Sign ReAlive " <<Nodeip;
                                cout <<SHAstg(NodeDir)+"00"+SHAstg(publicDirNode)+"00"+LastBlSHA+"00"+localtimestg;
                                break;
                            }

                            vector<uint8_t> byteArray = stringToBytes(stresponse);

                            peerssyncblocklock.lock();

                            auto iter  = Nodes.find(it->first);
                            if (iter != Nodes.end()){
                                Nodes[it->first].ip = Nodeip;
                                Nodes[it->first].logged = true;
                                
                            } else{
                                peerssyncblocklock.unlock();
                                break;
                            }
                            
                            //cout<<endl<<"connection ReAlive:" <<Nodeip<<endl;
                            ofstream filew("peer/" + Nodeip, ios::binary | ios::out);
                            if (!filew){ 
                                cout << "error al abrir la Db de dirs"; 
                                peerssyncblocklock.unlock();
                                break;  
                                }

                            for (unsigned int i = 0; i < byteArray.size(); i++){
                                filew.seekp(i);
                                filew.put(byteArray[i]);
                            }
                            filew.close();
                            peerssyncblocklock.unlock();
                            break;
                        }
                    }
                }
            }
        }
        ++it;
    }
}

string certRead(string bl){

    ifstream lastbdb("peer/" + bl, ios::binary | ios::in);
    char readChar;
    string blockread = "";
    if (!lastbdb) { return "no se cargo el archivo ";}
    for (unsigned int i = 0; i < 600; i++){
        lastbdb.seekg(i);
        lastbdb.get(readChar); // Leer el carácter en la posición actual
        blockread += readChar;
    }


    return blockread;
}

vector<string> blkOpSync(int x1,int x2,string ShaLBBBuffered){

    string ipquery = matchMinQueueIp();
    string random32hexstr = random32Hex();

    string  Sx1 = intToHex(x1);
    string  Sx2 = intToHex(x2);
    string  Sx3 = random32hexstr;

    string jsonval = "{\"x1\": \"" + Sx1 + "\", \"x2\": \"" + Sx2 + "\", \"x3\": \"" + Sx3 + "\"}"; 
    string response =  curlpost2("https://"+ipquery+"/queue" ,  jsonval , 1000);
    cout<<endl<<"response OpSync bl "<<ipquery << " x1 "<<Sx1<<" x2 "<<Sx2<< " " <<response<<endl;
    vector<string> result;

    if (response== "syncedToLastOp"|| response== "RefactorizingLastBl"){
        result.push_back(response);
        return result;
    }

    try {
        auto x = crow::json::load(response);

        if(response == "00"||x.size()==0){
            matchmingMistake();
            result.push_back("00");
            return result;
        }

        errorMatchminCount = 0;

        string msg_firm="";
        string jsonstring;
        int xsize = x.size();
        for(int i = 0; i<xsize;i++){

            jsonstring = x[i].s();

            if( (jsonstring.length()== 438||jsonstring.length()== 310|| jsonstring.length()== 136&&i==0  || i+1==xsize  ) &&xsize>1){

                // ultimo [] cuando es la firma
                if(i+1==xsize){

                    if(jsonstring.length()!=128){result.clear(); result.push_back("01"); 
                        cout<<endl<<"catch error debug jsonstring.length()!=128";
                        return result;
                    }
                    uint syncqueuesize = result.size();
                    for(uint e =0; e< syncqueuesize; e++){
                        msg_firm+= result[e];
                    }
                }

                result.push_back(jsonstring);

            } else{

                if(xsize == 2 ){
                    string str1 = x[0].s();
                    string str2 = x[1].s();

                    if(str1.length()==64 && str2.length() == 128 ){
                        if(verifySignature(str1, str2 ,  loadPublicKey(matchMinQueue().substr(2 , 128))) ){
                            cout<<endl<<"the node request to syncOp inst the matchmin";
                            result.clear(); result.push_back("02"); return result;
                        }
                    }

                } 
                cout<<endl<<"catch error debug xsize !=2 "<<endl<<jsonstring;

                result.clear(); result.push_back("01"); return result; 
            }
        
        }

        if( !verifySignature(Sx3+msg_firm, result[result.size()-1] ,  loadPublicKey(matchMinQueue().substr(2 , 128))) ){

            cout<<endl<< "Invalid sign in opsync downloaded from matchmin "<<endl<<"msg_firm "<<msg_firm<<
            endl<<" result[result.size()-1] "<<result[result.size()-1] <<endl<<
            matchMinQueue();

            result.clear(); result.push_back("01"); return result;
        }

    }
    catch (const std::exception& e) {
        matchmingMistake();
        cout<<endl<<"blkopsync error catch ";
        result.push_back("01");
        return result;
    }
    return result;

}

string addressIpDB(string &PublicAddress){

    for (const auto &entry : std::filesystem::directory_iterator("peer/")){
        if (entry.is_regular_file()){
            ifstream archivo(entry.path());
            if (archivo.is_open()){
                string linea="";
                vector<string>fila;
                vector<string>datos;
                getline(archivo, linea);
                archivo.close();
                if(SHAstg(PublicAddress)==linea.substr(0,64)){
                    return entry.path().filename().string();
                }
            }
        }
    }
    return "null";

}

bool saveNewNode(string PublicAddress){

    if(!HexCheck(PublicAddress)){
        return false;
    }

    if(PublicAddress.length()!=130){
        return false;
    }

    filesystem::path directory = "peer/PublicNode/";

    for (const auto &entry : std::filesystem::directory_iterator(directory)){
        if(entry.is_regular_file()){
            if(entry.path().filename().string() == PublicAddress){
                return true;
            }
        }
    }

    ofstream filew("peer/PublicNode/" + PublicAddress, ios::binary | ios::out);
    filew.close();

    for (const auto &entry : std::filesystem::directory_iterator(directory)){
        if(entry.is_regular_file()){
            if(entry.path().filename().string() == PublicAddress){
                return true;
            }
        }
    }

    return false;

}

bool EraseNode(string PublicAddress){

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);

    auto it = Nodes.begin();
    while (it != Nodes.end()) {

        if(it->first == PublicAddress ){

            for (const auto &entry : std::filesystem::directory_iterator("peer/PublicNode/")){

                if (entry.is_regular_file()){
                    if(entry.path().filename().string() == PublicAddress){
                        string ipIndex = addressIpDB(PublicAddress);
                        if( ipIndex != "null" ){
                            std::filesystem::remove("peer/"+ipIndex);
                        }
                        std::filesystem::remove("peer/PublicNode/"+PublicAddress);
                    }
                }
            }

            Nodes.erase(PublicAddress);
            return true;
        }

        ++it;

    }

    return false;

}

string paireNode( string PublicAddress , string ip){

    for (auto &acc : PublicAddress) { acc = std::toupper(acc);}
    filesystem::path directory = "peer/PublicNode/";
    for (const auto &entry : std::filesystem::directory_iterator(directory)){
        if (entry.is_regular_file()) {
            string PublicNodeDB = entry.path().filename().string();
            if (PublicNodeDB == PublicAddress){

                string localtimestg = timing();
                string LastBlSHA = shaLBB();
                string msg = SHAstg(publicDirNode)+"00"+SHAstg(PublicAddress)+"00"+LastBlSHA+"00"+localtimestg;
                string sig = LocalSigner(msg);
                msg = msg + "00" + sig;

                if (!verifySignature(msg.substr(0, 208), sig, loadPublicKey(publicDirNode.substr(2, 128)))){
                    return "signing_Error";
                }

                uint timeout_ms = 2000;

                string stresponse = curlpost2("https://" + ip + "/pair", msg, timeout_ms);

                if(stresponse.length()!= 210){
                    cout<<endl<<"invalid response "<<stresponse;
                }

                if (!verifySignature(SHAstg(PublicAddress)+"00"+SHAstg(publicDirNode)+"00"+LastBlSHA+"00"+localtimestg, stresponse.substr(210, 128), loadPublicKey(PublicAddress.substr(2, 128)))){
                    cout << "invalid signature" ;
                    cout << msg.substr(130,64)+"00"+msg.substr(0,64)+"00"+LastBlSHA+"00"+localtimestg+" signature "+stresponse.substr(340, 128);
                    cout<<endl<<"stresponse "<<stresponse;
                }

                vector<uint8_t> byteArray = stringToBytes(stresponse);
                // verificar flujo de entrada
                if (!loginPeer(stresponse, ip )){
                    return "Loggin_Error";
                }

                for (auto &acc : PublicNodeDB) {acc = std::toupper(acc); }
                string localNodeId = SHAstg(PublicNodeDB);
                for (const auto &entry2 : std::filesystem::directory_iterator("peer")){
                    if (entry2.is_regular_file()){
                        ifstream archivo2(entry2.path());
                        if (archivo2.is_open()){
                            string linea;
                            getline(archivo2, linea);
                            if(localNodeId==linea.substr(0 , 64)){
                                archivo2.close();
                                remove(entry2);
                            }
                            archivo2.close();
                        }
                    }
                }

                ofstream filew("peer/" + ip , ios::binary | ios::out);
                if (!filew){ 
                    return "error al abrir la Db de dirs";  
                }

                for (unsigned int i = 0; i < byteArray.size(); i++){
                    filew.seekp(i);
                    filew.put(byteArray[i]);
                }
                filew.close();
                return bytesToString(readFile("peer/" + ip ));
            }
        }
    }
    return "local saved address node not found";
}

uint PeersLogged(){

    int peerslogged=0;
    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    auto it = Nodes.begin();
    while (it != Nodes.end()) {
        if(it->second.ip =="unavailable"||it->second.ip =="" ){
            ++it;
            continue;
        }
        peerslogged++;
        ++it;
    }
    return peerslogged;
}

int ShaMinInit(){

    extern bool synced;
    extern int timingRound;
    extern string ShaLBBBuffered;
    int timeout_ms = 1000;
    vector<uint64_t> count;
    vector<int> timingroundNodesVector;
    string matchmax;

    cout<<endl<<"ShaMinInit check network";

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    auto Nodes2 = Nodes;
    peerssyncblocklock.unlock();

    auto it = Nodes2.begin();
    while (it != Nodes2.end()) {

        if( it->second.ip == "unavailable" || it->second.ip == "localhost"|| it->second.ip == "" ){
            ++it;
            continue;
        }

        string response = curlpost2("https://"+it->second.ip + "/peersMatchMin", "ShaMinInit", timeout_ms);

        if (response == "00") {
            cerr << "ShaMinInit() ; " << it->second.ip<<" no response "<<response<<endl;
            ++it;
            continue;
        }
            
        try {
    
            auto x = crow::json::load(response);
            string datastring = x[0].s();
            string shalb = x[1].s();
            string firmnode = x[2].s();
            string TimingRoundNode = x[3].s();


            // verificar firma del nodo

            if(!HexCheck(datastring)){
                cout<<endl<<" ShaMinInit() :"<< it->first << " bad form response :"<<datastring;
                ++it;
                continue;
            }
            if(shaLBB()!=shalb){
                cout<<endl<<" ShaMinInit() "<<it->first<< " invalid shalb resonse : "<<shalb<<endl<<"local is :"<<shaLBB();
                ++it;
                continue;
            }
            if(!verifySignature(datastring+shalb, firmnode ,  loadPublicKey(it->first.substr(2 , 128)))){
                cout<<endl<<"ShaMinInit() "+it->first+ " "+it->second.ip;
                ++it;
                continue;   
            }
            if(stoi(TimingRoundNode)>stoi(timing())+15){
                cout<<endl<<" ShaMinInit()invalid timing round data retrieved from node "<<it->first<< "  "<<TimingRoundNode;
                ++it;
                continue;
            }
            timingroundNodesVector.push_back(stoi(TimingRoundNode));
            count.push_back(hexToUint(datastring));

        } catch (const std::exception& e) {
            cout<<endl<<"invalid response from: "<< "https://"+it->second.ip+"/peersMatchMin ; "+response;
            ++it;
            continue;
        }   
        ++it;
        
    }

    timingroundNodesVector.push_back(timingRound);
    count.push_back(matchminRounInit);
    matchmax = MatchMaxIntValue2(count);
    if ((hexToInt(matchmax.substr(8 , 8))*10000)/Nodes2.size()>=5100){ 

        return hexToInt(matchmax.substr(0,8));

    } else {
        cout <<endl<<" ShaMinInit() fail verification entwork hexToInt(matchmax.substr(8 , 8))*10000)/Nodes2.size()>=5100 "<<matchmax;
    }

    return 2;
        
}

bool MatchCheckDW(){

    string peersstring="";
    std::unique_lock<std::mutex> peersMatchMinBlockmtxlock(peersMatchMinBlockmtx);
    for(int i =0; i<peersMatchMin.size();i++  ){
        peersstring+=peersMatchMin[i];
    }
    peersMatchMinBlockmtxlock.unlock();
    vector<string> shaqueue;
    string peersSha = SHAstg(peersstring);
    int timeout_ms = 1000;
    uint matchminroundIsNotInitInt =0;

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    auto Nodes2 = Nodes;
    peerssyncblocklock.unlock();

    auto it = Nodes2.begin();
    while (it != Nodes2.end()) {

        if(it->second.ip=="localhost"){
            //cout<<endl<<"debug matchcheckDW localhost sha "<<peersSha;
            shaqueue.push_back(peersSha);
            ++it;
            continue;
        }

        string response = curlpost2("https://"+it->second.ip+"/peersMatchMin", "SHA", timeout_ms);

        try {


            if (response == "00"){
                cout << endl<< "MatchCheckDW() "+it->second.ip+"/peersMatchMin SHA" << ": Response Fail. ";
                ++it;
                continue;
            }

            auto x = crow::json::load(response);

            string datastring = x[0].s();
            string shalb = x[1].s();
            string timingblock = x[2].s();
            string firmnode = x[3].s();

            if(!verifySignature(datastring+shalb+timingblock, firmnode ,  loadPublicKey(it->first.substr(2 , 128)))){
                cout<<endl<<" invalid sign from "<<it->first<< " response from: "<< "https://"+it->second.ip+"/peersMatchMin SHA";
                ++it;
                continue; 
            }

            if (datastring == "matchminroundIsNotInit"){
                matchminroundIsNotInitInt++;
            }else{
                shaqueue.push_back(datastring);
            }
        }     
        catch (const std::exception& e) {
            cout<<endl<<"MatchCheckDW() invalid response from: "<< "https://"+it->second.ip+"/peersMatchMin SHA "+response;
            ++it;
            continue;
        }
        ++it;
    }
    
    string maxsha = MatchMaxString(shaqueue);
    //cout<<endl<<"matchcheckDW maxsha "<<maxsha<<endl;

    if ((matchminroundIsNotInitInt*10000 )/Nodes2.size()>=5000){
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return MatchCheckDW();
    }

    if( (hexToInt(maxsha.substr(0,8))*10000 )/Nodes2.size()<5100 ){
        cout<<endl<<"MatchCheckDW maxsha fail result: "<< (hexToInt(maxsha.substr(0,8))*10000 )/Nodes2.size() <<"%" ;
        return false;;
    }
    if(maxsha.substr(8,64) == peersSha){
        return true;
    }
    return false;
    
}

void clearMatchminProposal(){

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);

    if(shaMatchMinproposalReveled){
        shaMatchMinproposal= "";
    }
    matchminbuilt = false;
    shaMatchMinproposalReveled=false;
    matchminSortRound.clear();
    matchminProposalArrengelStr="";
    matchminsorted="";

    auto it = Nodes.begin();
    while (it != Nodes.end()) {
        it->second.ShaMinProposal[lastbl] = "";
        ++it;
    }
}


// 1 sha result definition
bool NextMatchMinNetwork(){

    uint8_t triesMax = 3;
    for(uint8_t tries =0; tries<triesMax; tries++){

        std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
        auto Nodes2 = Nodes;
        peerssyncblocklock.unlock();

        auto it = Nodes2.begin();
        while (it != Nodes2.end()) {
            if(it->second.ip== "localhost"){
                if(shaMatchMinproposal.length() != 64 || !HexCheck(shaMatchMinproposal) ){
                    shaMatchMinproposal = random32Hex();
                } 
                ++it;
                continue;
            }

            if(Nodes2[it->first].ShaMinProposal[lastbl].length()==64 || Nodes2[it->first].ip == "unavailable"){
                ++it;
                continue;
            }

            string Sx1 = "ShaMinPush";
            string Sx2 = uint64ToHex( lastbl+1);
            string Sx3 = random32Hex();
            string Sx4 = LocalSigner(Sx1+Sx2);
            string jsonval = "{\"x1\": \"" + Sx1 + "\", \"x2\": \"" + Sx2 + "\", \"x3\": \"" + Sx3 + "\", \"x3\": \"" + Sx4 + "\"}"; 

            string response = curlpost2("https://"+it->second.ip + "/peersMatchMin", jsonval, 400);

            // cout << endl<< " NextMatchMinNetwork response "<<it->second.ip<< " "<< response;

            if (response == "00") {
                cerr << " response from " << it->second.ip<<" "<<response;
                ++it;
                continue;
            }
            try {
                auto x = crow::json::load(response);
                string blShaMin = x[0].s();
                string SignRes = x[1].s();
                if(blShaMin.length()!=64){
                    cout<<endl<<"invalid blShaMin to ShaMinPush "<<it->first;
                    ++it;
                    continue;
                }
                if( !verifySignature( Sx1+Sx2+Sx3+blShaMin,  SignRes ,  loadPublicKey(it->first.substr(2,128))) ){
                    cout<<endl<<"invalid signature to ShaMinPush "<<it->first;
                    ++it;
                    continue;
                }
                peerssyncblocklock.lock();
                auto iter  = Nodes.find(it->first);
                if (iter != Nodes.end()){



                    Nodes[it->first].ShaMinProposal[lastbl] = blShaMin;



                }
                peerssyncblocklock.unlock();

                ++it;
            } catch (const std::exception& e) {
                ++it;
            }
        }
    }
    return true;
}

string ArrangeStringOfProposals(){

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    std::unique_lock<std::mutex> peersMatchMinBlockmtxlock(peersMatchMinBlockmtx);
    string arregle = "";

    for(uint i = 0;i < peersMatchMin.size(); i++ ){

        auto iter = Nodes.find(peersMatchMin[i]);
        if (iter != Nodes.end()){
            if(iter->second.ip == "localhost"){
                //cout<<endl<<iter->second.ip<<" ; " <<SHAstg(shaMatchMinproposal);
                arregle += SHAstg(shaMatchMinproposal);
                continue;
            }
            //cout<<endl<<iter->second.ip<<" ; " << iter->second.ShaMinProposal[lastbl];
            arregle += iter->second.ShaMinProposal[lastbl];
        }
    } 

    return arregle ;
}

// 2 sha result string definition on network
uint8_t checkMatchMinStringListNetwork(string sortResult, string apiquery){

    vector<string> shaqueue;
    string peersSha = SHAstg(sortResult);
    int timeout_ms = 1000;
    uint matchminroundIsNotInitInt =0;

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    auto Nodes2 = Nodes;
    peerssyncblocklock.unlock();

    auto it = Nodes2.begin();
    while (it != Nodes2.end()) {

        if(it->second.ip=="localhost"){
            shaqueue.push_back(peersSha);
            ++it;
            continue;
        }

        if( it->second.ip == "unavailable"){
            ++it;
            continue;
        }

        string Sx1 = apiquery;
        string Sx2 = uint64ToHex(lastbl);
        string Sx3 = random32Hex();

        string jsonval = "{\"x1\": \"" + Sx1 + "\", \"x2\": \"" + Sx2 + "\", \"x3\": \"" + Sx3  + "\"}"; 
        string response = curlpost2("https://"+it->second.ip+"/peersMatchMin", jsonval, timeout_ms);
        //cout << endl<< " checkMatchMinStringListNetwork response "<<it->second.ip<<" "<<apiquery<< " "<< response;

        try {
            auto x = crow::json::load(response);

            if (response == "00"){
                cout << endl<< it->second.ip << ": Response Fail. ";
                ++it;
                continue;
            }

            string ResponseQuery = x[0].s();
            string signature = x[1].s();

            if(!verifySignature(Sx1+Sx2+Sx3+ResponseQuery, signature ,  loadPublicKey(it->first.substr(2 ,128)))){
                cout<<endl<<"invalid signature from "<<it->second.ip<< " response from: "<< "https://"+it->second.ip+"/peersMatchMin  "+apiquery+" : "<<response;
                ++it;
                continue; 
            }

            if (ResponseQuery.length() != 64){
                matchminroundIsNotInitInt++;
                
            }else{
                shaqueue.push_back(ResponseQuery);
            }
        }catch (const std::exception& e) {
            cout<<endl<<"invalid response from: "<< "https://"+it->second.ip+"/peersMatchMin";
        }
        ++it;
    }
    
    string maxsha = MatchMaxString(shaqueue);
    //cout<<endl<<"checkMatchMinStringListNetwork maxsha "<<maxsha<<endl;
    peerssyncblocklock.lock();

    if ( ((matchminroundIsNotInitInt)*10000)/Nodes.size()>=5000 ){
        cout<<endl<<"checkMatchMinStringListNetwork Ok Result : "<< (matchminroundIsNotInitInt*10000)/Nodes.size() <<"%";
        return 0;
    }

    if( (hexToInt(maxsha.substr(0,8))*10000 )/Nodes.size()<5100 ){
        cout<<endl<<"checkMatchMinStringListNetwork Fail Result : "<< (matchminroundIsNotInitInt*10000)/Nodes.size() <<"%";
        return 2;
    }
    if(maxsha.substr(8,64) == peersSha){
        return 1;
    }
    return 0;
    
}

// 3 get presha of each proposal
bool GetMatchMinNetwork(){

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
    auto Nodes2 = Nodes;
    peerssyncblocklock.unlock();

    auto it = Nodes2.begin();
    while (it != Nodes2.end()) {

        auto iter  = matchminSortRound.find(it->first);
        if (iter != matchminSortRound.end()){
            if(iter->second.length() == 64){
                ++it;
                continue;
            }
        }

        if(it->second.ip == "localhost"){
            matchminSortRound[it->first]=shaMatchMinproposal;
        }

        if( it->second.ShaMinProposal[lastbl].length() != 64 || it->second.ip == "unavailable" ){
            ++it;
            continue;
        }

        string Sx1 = "ShaMinGet";
        string Sx2 = uint64ToHex( lastbl);
        string Sx3 = random32Hex();
        string Sx4 = LocalSigner(Sx1+Sx2);
    
        string jsonval = "{\"x1\": \"" + Sx1 + "\", \"x2\": \"" + Sx2 + "\", \"x3\": \"" + Sx3 + "\", \"x3\": \"" + Sx4 + "\"}"; 

        //cout<<endl<<"req to https:// "<<it->second.ip+ "/peersMatchMin";

        string response = curlpost2("https://"+it->second.ip + "/peersMatchMin", jsonval, 400);

        //cout<<endl<<"res from https:// "<<it->second.ip+ "/peersMatchMin - getmatchmin "+response;

        if (response == "00") {
            cerr << " ShaMinGet :" << it->second.ip<<" Fail response"<<endl;
            //add node to bad response
            ++it;
            continue;
        }
            
        try {
            auto x = crow::json::load(response);
            string blShaMin = x[0].s();
            string SignRes = x[1].s();

            if( !verifySignature( Sx1+Sx2+Sx3+blShaMin,  SignRes ,  loadPublicKey(it->first.substr(2,128))) ){
                cout<<endl<<"ShaMinGet : "+ it->first+" invalid signature response";
                ++it;
                continue;
            }

            if( SHAstg(blShaMin) == it->second.ShaMinProposal[lastbl] ){

                cout<<endl<<" GetMatchMinNetwork() " <<it->first+" validate Sha. "+blShaMin;
                matchminSortRound[it->first] = blShaMin;

            } else{
                //add node to bad response
                cout<<endl<<" GetMatchMinNetwork() " <<it->first+" Sha  Deny "+blShaMin;
            }

            ++it;

        } catch (const std::exception& e) {
            ++it;
        }
    }

    return true;
}

//4.1 build string shamin
string MatchMinStringList(){

    std::unique_lock<std::mutex> peersMatchMinBlockmtxlock(peersMatchMinBlockmtx);

    string sortResult="";

    for(uint i = 0; i<peersMatchMin.size();i++){
        if(matchminSortRound[peersMatchMin[i]].length() == 64 ){
            sortResult+= matchminSortRound[peersMatchMin[i]];
        }
    }

    return sortResult;

}

void matchMinBuildQueue2(){

    std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);

    string shavalue = matchminsorted;
    std::unique_lock<std::mutex> peersMatchMinBlockmtxlock(peersMatchMinBlockmtx);
    peersMatchMin.clear();
    vector<string>collectdata;
    auto it = Nodes.begin();
    while (it != Nodes.end()) {

        collectdata.push_back(it->first);
        ++it;

    }
    uint nodessize = Nodes.size();
    
    peerssyncblocklock.unlock();

    for(uint i = 0;i < nodessize; i++ ){

        string matchminresult = matchMin2( shavalue , collectdata);
        shavalue+=SHAstg(shavalue+matchminresult);
        peersMatchMin.push_back(matchminresult);

        for (uint e = 0; 0 < collectdata.size(); e++){
            if(collectdata[e] == matchminresult ){
                collectdata.erase(collectdata.begin() + e);
                break;
            }
        }
    } 

    return  ;
}

bool sortMatchMin(){

    extern uint shamatchinstep;

    shamatchinstep = 0;

    matchMinBuildQueue();

    //shamin push
    if(!NextMatchMinNetwork()){
        cout<<endl<<"NextMatchMinNetwork() init fail";
        return false;
    }


    //cout<<endl<<"sortMatchMin: pushMatchMin OK"<<endl;

    //arrange string from sha
    matchminProposalArrengelStr = SHAstg(ArrangeStringOfProposals());

    shamatchinstep = 1;
    //check matmin list push
    for (uint8_t tries=0; tries< 5; tries++ ){
        uint8_t result = checkMatchMinStringListNetwork(matchminProposalArrengelStr,"SHAsort");
        if ( result== 1 ){
            break;
        }
        if ( result == 2 ){
            cout<<endl<<"sortMatchMin-SHAsort : string rejected by network";
            return false;                                                                                 
        }
        if( tries >3 ){
            cout<<endl<<"sortMatchMin-SHAsort : Max attempts reached  ";
            return false;
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    shamatchinstep = 3;
    
    // check matchminbuilded true network
    matchminbuilt = true;
    //cout<<endl<<"sortMatchMin SHAsort OK"<<endl;

    //get matchmin presha
    for (uint8_t tries=0; tries< 5; tries++ ){
        if (GetMatchMinNetwork()){
            if((matchminSortRound.size()*10000)/Nodes.size() >= 10000){
                break;
            }
        }

        if(tries >3){
            if((matchminSortRound.size()*10000)/Nodes.size() >= 5100){
                break;
            }
            cout<<endl<<"GetMatchMinNetwork fail result: "<<(matchminSortRound.size()*10000)/Nodes.size()<<"%";
            return false;
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

        shamatchinstep = 4;

    cout<<endl<<"GetMatchMinNetwork() OK result: "<<(matchminSortRound.size()*10000)/Nodes.size()<<"%";

    matchminsorted = MatchMinStringList();

    // build random nodes queue
    matchMinBuildQueue2();


    //check matchmin sorted network

    for (uint8_t tries=0; tries< 5; tries++ ){
        uint8_t result = checkMatchMinStringListNetwork(matchminsorted,"FinalMatchminArrengle");
        if ( result== 1 ){
            break;
        }
        if ( result== 2 ){
            cout<<endl<<"sortMatchMin-matchminsorted : string rejected by network"<<endl;
            return false;
        }
        if( tries >3 ){
            cout<<endl<<"sortMatchMin-matchminsorted  : tries fail"<<endl;
            return false;
        }
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }

    shamatchinstep = 5;

    //cout<<endl<<"sortmatchMin()  "<<(matchminSortRound.size()*10000)/Nodes.size()<<endl;

 

    return true;

}

#endif


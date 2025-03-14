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


#ifndef CryptoDbSS_H
#define CryptoDbSS_H

#include <array>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <forward_list>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <pthread.h>
#include <string>
#include <sstream>
#include <thread>
#include <vector>

#include "crow.h"

#include "codec.h"
#include "key.h"
#include "strucc.h"
#include "compresion.h"
#include "firewall.h"
#include "setnod.h"
#include "hasher.h"
#include "func.h"
#include "blockreader.h"
#include "IndexingEngine.h"
#include "match.h"
#include "transacALG.h"
#include "peersasync.h"
#include "threadsdw.h"
#include "TransactionType.h"
#include "serverFunc.h"

using namespace std;

const string version = "MVP_0.0.1";
const string idblockchainName = "CDB256SS::TEST-BLOCKCHAIN";
vector<unsigned char> IdBlkchain = sha3_256v(stringToBytes(idblockchainName));
const string idBlckchn = vectorstring(IdBlkchain);

uint64_t lastbl = lastblockbuilt();
uint16_t blksize = maxblks();
const uint16_t maxblksize = 65534;// <= 65534
uint16_t maxCompPoint = 2; // maxCompPoint <= 65534
int transacmaxtime = maxclientresp();
uint shablbmaxbuffer = shablbmaxbufferset();
uint accIndexMaxCache = accIndexMaxCacheset();
uint64_t timingbl;
uint64_t Maxtimingbl=GetTimingBlSetting();
int port = portset();
string dir_feeds = feedToDirset();
uint feeds_ratio = feedRatioset();
int timingRound = stoi(timing())+9999;
uint16_t errorMatchminCount = 0;

vector<string> peersMatchMin;// client node

bool synced=false;
bool syncing=false;
bool syncqueue = false;
bool matchminRounInit = false;
bool comfirmOptrancasyncRun=false;
bool statusCheckRun=false;
bool lastblockbuiltBlock=false;
bool postRefactRoundInit = false;
bool refactSHA = false;
bool Refactorizing;
unsigned long long lastblDWULL;
uint syncOpNumbr = 0;

int32_t transacsconfirmed = 0;
int32_t transacpendingcount = 0;
int32_t pretransacpending = 0;

uint wirtespacecount = 0;
uint queuReq = 0;
string publicDirNode = "";
vector<unsigned char> blRefactHashed=LastblRefactUncompressedHashed();

string* blksOP = new string[maxblksize];
vector<string>MatchminTransacs;
vector<string>blksOPSync;
vector<string>blksOPSyncQueue;

int const timeout_ms = 1000;

// CACHE Sha-Blocks
string LBBBuffered = blread(to_string(lastbl));
vector<unsigned char> ShaLBBBufferedArr(40);
map<int, string> shablbbuffer;
map<uint64_t, array<unsigned char, 32>> shablbbuffer2;

string ShaLBBBuffered=shaLBB();
string F256="";
bool OnlyLocalApi = false;

///Mutex 
mutex writingspace;
mutex blkQueuemtx; // blksOPSyncQueue
mutex WritingAccSync;
mutex queuetransacsmtx;
mutex MatchminTransacsmtx;
mutex peerssyncblock;
mutex pricesingtransacCount;
mutex queueIpMtx;
mutex allowIpmtx;
mutex shaLBBmtx;
mutex ShaBlBmtx;
mutex cryptomtx;
mutex randommtx;
mutex queuReqmtx; // queuReqmtx
mutex blRefactHashedBlockmtx;
mutex peersMatchMinBlockmtx;

bool BlAntIsMatch=false;

map< array <unsigned char,64>, dbstruct >mapIndex;
map< array <unsigned char,64>, Accsync >AccSync;

time_t* transactime = new time_t[maxblksize];
int lastmatchsyncqueue =0;
map<string, string> queuetransacs;
vector <string> queueIp;
map<int,bool>checkTransacSync;
map<uint16_t,bool> numberspace;

//pre sha revealed
map<string ,string> matchminSortRound;
map<string,nodeStruct> Nodes;
string shaMatchMinproposal = "";
bool matchminbuilt = false;
bool shaMatchMinproposalReveled = false;
string matchminsorted = "";
string matchminProposalArrengelStr = "" ;
uint shamatchinstep;


//firewall vars
//////////////////////////////////////////////

unordered_map<string, ReqIp> AllowIp;
unordered_map<string, uint> WarningIp;
forward_list<string> BanIp;

uint loginAlg = 160;
uint transcAlg = 2400;
uint syncTransacAlg =150;
uint front =120;
uint balanceindex = 20;
uint blocksearch=64;
uint status=1200;
bool firewallcheck;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

int listener(){

    crow::SimpleApp app;
              
                                           //Rutas https

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //node login
    
    CROW_ROUTE(app, "/pair").methods("POST"_method)([](const crow::request &req, crow::response &res){

    string nodeId = req.body;
    res.set_header("Content-Type", "text/plain");
    for (auto &acc : nodeId) {acc = toupper(acc); }
    string ip = req.remote_ip_address; 
    string fw=firewall(ip, "loginAlg");

    if( fw == "true"){

        vector<uint8_t> byteArray = stringToBytes(nodeId);

        filesystem::path directory = "peer/PublicNode/";
        for (const auto &entry : filesystem::directory_iterator(directory)){
            if(entry.is_regular_file()){

                string nodeDir = entry.path().filename().string();
                for (auto &acc : nodeDir) {acc = toupper(acc); }
                string localNodeId = SHAstg(nodeDir);
                
                if(localNodeId==nodeId.substr(0,64)){

                    if(SHAstg(publicDirNode)==nodeId.substr(66,64)){

                        if(stoi(timing())>stoi(nodeId.substr(198,10))+300||stoi(timing())<stoi(nodeId.substr(198,10))-300){
                            cout<<endl<<"invalid date from node "<<timing()<<" "<<nodeId.substr(198,10)<<endl;
                            res.body = "Invalid timing date";
                            return res.end();
                        }

                        if(!verifySignature(nodeId.substr(0,208),nodeId.substr(210,128), loadPublicKey(nodeDir.substr(2,128)))){
                            res.body = "Invalid_signature_paire";
                            cout<<endl<<nodeId<<endl;
                            return res.end();
                        }
                        string localtimestg = timing();
                        
                        //cout<<endl<<"debug localtimestg "<<localtimestg <<" "<< nodeId.substr(198,10)<<endl;

                        string msg = SHAstg(publicDirNode)+"00"+SHAstg(nodeDir)+"00"+nodeId.substr(132,64)+"00"+nodeId.substr(198,10);  
                        string sig =LocalSigner(msg);
                        string responser = msg+"00"+sig;

                        for (const auto &entry2 : filesystem::directory_iterator("peer")){
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
                                        
                        ofstream filew("peer/"+ip+":18090" , ios::binary | ios::out);
                        if (!filew){cout<<"error al abrir la Db de dirs"; return res.end(); }
                        for (unsigned int i = 0; i < byteArray.size(); i++) { 
                            filew.seekp(i); 
                            filew.put(byteArray[i]); 
                        }
                        filew.close();

                        string stringread = bytesToString(readFile("peer/"+ip+":18090"));

                        if(loginPeer(nodeDir,ip)){
                            cout<<endl<<" peer logged: "<<ip<< " - "<<nodeDir;
                            res.body = responser;
                            return res.end();
                        } 

                        cout<<endl<<"!loginpeer_Error: "<<ip<<endl;
                        responser = "loginpeer_Error";
                        res.body = responser;
                        return res.end();
                    }
                } else { 
                    cout<<endl<<"unknown address login "<<localNodeId<<" "<<nodeId.substr(0,64)<< endl;
                }
            } else { 
                cout<<endl<<"entry.is_regular_file()";
            }
        }
        cout<<endl<<"Reject Req-res "<<req.remote_ip_address<<endl;

        res.body = "Unautorized_Call";
        return res.end(); 
    }
        res.body = fw;
        return res.end(); 

    });
    CROW_ROUTE(app, "/ItsAlive").methods("POST"_method)([](const crow::request &req, crow::response &res){

        string nodeId = req.body;
        string ipport =req.remote_ip_address;

        string fw=firewall(req.remote_ip_address, "loginAlg");

        if( fw == "true"){

            // cout<<endl<<"nodeId.substr(0,130)==ipDir(req.remote_ip_address,peersObj) :"<< endl;
            // cout<<"debug ItsAlive "<<nodeId.substr(0,130)+" "+ipDir(ipport,peersObj)<<endl;
            if(nodeId.substr(0,130)==ipDir(ipport)){

                res.set_header("Content-Type", "text/plain");
                for (auto &acc : nodeId) {acc = toupper(acc);}
                if(!HexCheck(nodeId)){
                res.body = "Bad_Format_1";
                return res.end(); }

                if(nodeId.length()!=470){
                res.body = "Bad_Format_2";
                return res.end(); }

                //cout<<endl<<"nodeId.substr(132,130)==publicDirNode  "<< nodeId.substr(132,130)+" " +publicDirNode<<endl;
                if(nodeId.substr(132,130)==publicDirNode){
                    string requier = req.remote_ip_address;
                    //cout<<endl<<"requier debug "<<requier+":18090"<<endl;
                    //cout<<endl<<"stoi(nodeId.substr(330,10))<stoi(timing())-300 || stoi(nodeId.substr(330,10))>stoi(timing())+300 "<< nodeId.substr(330,10)+" "+timing()<<endl;
                    if(stoi(nodeId.substr(330,10))<stoi(timing())+300 && stoi(nodeId.substr(330,10))>stoi(timing())-300){
                        // cout<<endl<<"valid cert time"<<endl;
                        cout<<endl<<"verify signature"<<endl;
                        if(verifySignature(nodeId.substr(0, 340), nodeId.substr(342, 128), loadPublicKey(ipDir(req.remote_ip_address).substr(2, 128)))){
                            //cout<<endl<<"Alive Connection succes "<<endl;
                            string msg = publicDirNode+"00"+ipDir(req.remote_ip_address)+"00"+nodeId.substr(264 , 64)+"00"+timing();
                            for (auto &c:msg){c=toupper(c);}
                            res.body =msg+"00"+LocalSigner(msg);
                            // cout<<endl<<"ItsAlive Res: "<<res.body<<endl;
                            return res.end(); 
                        } else {
                            cout<<endl<<"/ItsAlive reject verifySignature(nodeId.substr(0, 340), nodeId.substr(342, 128), loadPublicKey(ipDir(req.remote_ip_address,peersObj).substr(2, 128)))"<<endl;
                        }
                    } else {
                        cout<<endl<<"/ItsAlive reject stoi(nodeId.substr(330,10))<stoi(timing())+300 && stoi(nodeId.substr(330,10))>stoi(timing())-300)"<<endl; 
                    }
                } else {
                    cout<<endl<<"/ItsAlive reject nodeId.substr(132,130)==publicDirNode"<<endl;    
                }
            } else {
                cout<<endl<<"/ItsAlive reject nodeId.substr(0,130)==ipDir(ipport,peersObj)"<<endl; 
            }
            cout<<endl<<"Req ip : "<<req.remote_ip_address;
            cout << endl<< "Reject unauthorized call ItsAlive" << endl;
            res.body = "Unauthorized call";
            return res.end(); 
    }
        res.body = fw;
        return res.end(); 

    });    
    // node Sync
    CROW_ROUTE(app, "/peersMatchMin").methods("POST"_method)([](const crow::request &req){

            string reqbody = req.body;

            if(reqbody == "ShaMinInit"){

                vector<string> peerssha;
                peerssha.push_back(intToHex(matchminRounInit));
                peerssha.push_back(shaLBB()); 
                peerssha.push_back(LocalSigner(intToHex(matchminRounInit)+shaLBB()));
                peerssha.push_back(intToHex(timingRound));
                crow::json::wvalue response;
                response = peerssha;
                return crow::response(response); 
            }

            if(reqbody == "blRefactHash"){
               unique_lock<mutex> blRefactHashedBlockmtxlock(blRefactHashedBlockmtx);
                string blrefacthashedstr = bytesToString(blRefactHashed);
                return crow::response(blrefacthashedstr);
            }

            if (Refactorizing) {
                crow::response("Refactorizing new block please wait a moment and try again"); 
            }

            crow::json::wvalue response;

            if(reqbody == "SHA"){

                string peersstring="";
                unique_lock<mutex> peersMatchMinBlockmtxlock(peersMatchMinBlockmtx);
                for(int i =0; i<peersMatchMin.size();i++  ){
                    peersstring+=peersMatchMin[i];
                }
                
                cout<<endl<<"debug call /peersmatchmin SHA "<<peersstring<<endl;
                vector<string> peerssha;

                if(shamatchinstep>4){
                    peersstring = SHAstg(peersstring);
                } else {
                    peersstring = "matchminroundIsNotInit";
                }

                string firm = LocalSigner(peersstring+shaLBB()+uintToHex(timingbl));
                peerssha.push_back(peersstring);
                peerssha.push_back(shaLBB());
                peerssha.push_back(uintToHex(timingbl));
                peerssha.push_back(firm);
                peerssha.push_back(to_string(timingRound));

                response = peerssha;

            }

            if(reqbody == "Dir"){
                vector<string> peersstring;
                unique_lock<mutex> peersMatchMinBlockmtxlock(peersMatchMinBlockmtx);
                for(int i =0; i<peersMatchMin.size();i++  ){
                    peersstring.push_back(peersMatchMin[i]);
                } cout<<endl;

                response = peersstring;

            }

            try {
                auto x = crow::json::load(reqbody);
                string ApiQuery = x["x1"].s();
                vector<string> resp;

                cout<<endl<< "debug call persmatchmin "<<ApiQuery<<endl;

                if(ApiQuery == "ShaMinPush"){
                    string shaquerystr = x["x2"].s();
                    uint64_t shaquery = hexToUint64(x["x2"].s());
                    string random32HEX = x["x3"].s();
                    if(synced){

                        if(shaquery <= lastbl+2 && shaquery >= lastbl-2 && lastbl>=2 &&lastblDWULL+1 == shaquery ){
                            string elementquery;

                            if(shaMatchMinproposal.length() != 64){
                                shaMatchMinproposal = random32Hex();
                            } 

                            elementquery = SHAstg(shaMatchMinproposal);
                            resp.push_back(elementquery);
                            resp.push_back(LocalSigner( ApiQuery + shaquerystr + random32HEX + elementquery));
                            response = resp;
                            return crow::response(response);
                            
                        }
                    }
                } 

                if(ApiQuery == "ShaMinGet"){
                    string shaquerystr = x["x2"].s();
                    uint64_t shaquery = hexToUint64(x["x2"].s());
                    string random32HEX = x["x3"].s();
                    if(synced){
                        if((shaquery <= lastbl+2 || (shaquery >= lastbl-2 && lastbl>=2 ))&&lastblDWULL == shaquery ){
                            
                            string elementquery = "noreadyet "+ to_string(shamatchinstep) ;

                            if(shaMatchMinproposal.length() == 64 && matchminbuilt){

                                shaMatchMinproposalReveled =true;
                                elementquery = shaMatchMinproposal;

                            } 

                            resp.push_back(elementquery);
                            resp.push_back(LocalSigner( ApiQuery + shaquerystr + random32HEX + elementquery));
                            response = resp;
                            return crow::response(response);
                        }
                    }
                } 
                
                if(ApiQuery == "SHAsort"){
                                                
                    string shaquerystr = x["x2"].s();
                    uint64_t shaquery = hexToUint64(x["x2"].s());
                    string random32HEX = x["x3"].s();
                    string responsequery = "sincync";
                    if(synced){
                        responsequery = "bad req or unsynced";
                        if( lastbl == shaquery &&lastblDWULL == shaquery ){
                            string elementquery;
                            responsequery = "noreadyet "+to_string(shamatchinstep) ;

                            if ( matchminProposalArrengelStr.length() == 64){
                                responsequery= SHAstg(matchminProposalArrengelStr);
                            }
                        }
                    }
                    resp.push_back(responsequery);
                    resp.push_back(LocalSigner( ApiQuery + shaquerystr + random32HEX + responsequery));
                    response = resp;
                    return crow::response(response); 
                }
            
                if(ApiQuery == "FinalMatchminArrengle"){
                    string shaquerystr = x["x2"].s();
                    uint64_t shaquery = hexToUint64(x["x2"].s());
                    string random32HEX = x["x3"].s();
                    string elementquery = "sinlastblcync";
                    if(synced){
                        elementquery = "bad req or unsynced";
                        if( lastbl == shaquery &&lastblDWULL == shaquery ){
                            elementquery = "noreadyet "+to_string(shamatchinstep);

                            unique_lock<mutex> peerssyncblocklock(peerssyncblock);
                            if ( matchminsorted.length()> 63){
                                elementquery= SHAstg(matchminsorted);
                            }
                            peerssyncblocklock.unlock();
                        }
                    }
                    resp.push_back(elementquery);
                    resp.push_back(LocalSigner( ApiQuery + shaquerystr + random32HEX + elementquery));
                    response = resp;
                    return crow::response(response); 
                }

            } catch (const exception& e) {

            }

            return crow::response(response); 

    }); 
    CROW_ROUTE(app, "/lastBlLocal").methods("POST"_method, "GET"_method)([](const crow::request &req, crow::response &res){

    string ip = req.remote_ip_address; 
    string fw=firewall(ip, "loginAlg");

    if( fw == "true"){

        unique_lock<mutex> peerssyncblocklock(peerssyncblock);\
        auto Nodes2 = Nodes;
        peerssyncblocklock.unlock();

        auto iter  = Nodes.find(ipDir(ip));
        if (iter != Nodes.end()){

            string pass = req.body;
            string lblocal = ullToHex(lastblockbuilt());
            string firm = LocalSigner(pass+lblocal);

            res.body = lblocal+firm;
            return res.end();
        }
    }

    });

    //  per ip 60
    
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Transac algoritm
    // 

    CROW_ROUTE(app, "/GetDataTransac").methods("POST"_method)([](const crow::request &req, crow::response &res){

        // allow
        //////////////////////////////////////////////////////////////////////////////
       
        string fw=firewall(req.remote_ip_address, "transcAlg");

        res.set_header("Content-Type", "text/plain");

        if( fw == "true"){

           res.body =  GetDataTransac(req.body, req.remote_ip_address );
            return res.end(); 

        }

        res.body = fw;
        return res.end(); 

    
    });
    CROW_ROUTE(app, "/block").methods("POST"_method)([](const crow::request &req, crow::response &res){


        res.set_header("Content-Type", "text/plain");
        // allow
        //////////////////////////////////////////////////////////////////////////////

        string fw=firewall(req.remote_ip_address, "transcAlg");

        if( fw == "true"){

            res.body =  GetDataTransacAuth(req.body, req.remote_ip_address );
            return res.end(); 

        }
        
        res.body = fw;
        return res.end(); 

    });
    CROW_ROUTE(app, "/TransacSignedPost").methods("POST"_method)([](const crow::request &req, crow::response &res){

       // cout << endl << "transacSignedPost call =====>"<<endl;

        res.set_header("Content-Type", "text/plain");

        string fw=firewall(req.remote_ip_address, "transcAlg");

        if( fw == "true"){

            res.body = TransacSignedPost(req.body, req.remote_ip_address);
            return res.end(); 
        }

        res.body = fw;
        return res.end();


    });
    //2400 req per ip
    ////sync transac alg
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // 64 x min
    CROW_ROUTE(app, "/queuetransacs").methods("POST"_method)([](const crow::request &req, crow::response &res){

        //cout<<endl<<"callig queuetransacs debug =====>";

        // allow
        //////////////////////////////////////////////////////////////////////////////

        res.set_header("Content-Type", "text/plain");
        string fw=firewall(req.remote_ip_address, "syncTransacAlg");

        if( fw == "true"){

            if (Refactorizing) {
                res.body = "Refactorizing new block please wait";
                res.set_header("Content-Type", "text/plain");
                res.end();
            }

            string stg1 = req.body;

            //cout<<endl<<"debug /queuetransacs req.body "<<req.body.length()<< " "<< req.body<<endl;

            //verificar si reqbody es compatible con length
            if(!HexCheck(req.body)|| stg1.length() != 64){
                cout<<endl<<"Wrong data request"<<endl;
                res.body = "Wrong data request";
                res.set_header("Content-Type", "text/plain");
                res.end();
            }
            unique_lock<mutex> queueIpMtxlock(queueIpMtx);
            bool checkip;
            for(int i = 0; i<queueIp.size(); i++){
              
                if(queueIp[i]==req.remote_ip_address){
                    checkip=true;
                    break;
                }
            }
            queueIpMtxlock.unlock();
            if(!checkip){
                res.body = "No hay ninguna transaccion realizandose para esta direccion";
                res.set_header("Content-Type", "text/plain");
                res.end();
            }

            unique_lock<mutex> queuetransacsmtxlock(queuetransacsmtx);

            auto it = queuetransacs.find(req.body);
            if (it != queuetransacs.end()) {

            } else {
                res.body = "No hay ninguna transaccion realizandose para este id de transaccion";
                res.set_header("Content-Type", "text/plain");
                res.end();
            }

            /////////////////////////////////////////////////////////////////////////////

            //cout<<endl<<"req.body "<<req.body;
            //cout<<endl<<"res.body "<<queuetransacs[req.body];

            res.body = queuetransacs[req.body];

            if(queuetransacs[req.body].length() == 64 && HexCheck(queuetransacs[req.body])||queuetransacs[req.body] == "processing" ){
                res.body = "processing";
                return res.end();
            }

            if(queuetransacs[req.body].length() != 64 ){

                if (preDatalengthIsValid(queuetransacs[req.body])) {
                    unique_lock<mutex> MatchminTransacsmtxlock(MatchminTransacsmtx);
                    MatchminTransacs.push_back(res.body);
                }

               //cout<<endl<<"erasing queuetransacs element- id: "<<req.body<<endl;
                queuetransacs.erase(req.body);
            }

           // cout<<endl<<"queuetransacs[res.body] response : "<<res.body<<endl;
        
            return res.end();
        }

        res.body = fw;
        return res.end();


    });
    //64 x min
    //queue network sync
    CROW_ROUTE(app, "/queue").methods("POST"_method)([](const crow::request &req){

        // cout<<endl<<"<======= call req /queue"<<endl;
        string ip = req.remote_ip_address; 
        string fw=firewall(req.remote_ip_address, "syncTransacAlg");

        if( fw == "true"){

            unique_lock<mutex> peerssyncblocklock(peerssyncblock);
            auto Nodes2 = Nodes;
            peerssyncblocklock.unlock();

            auto it = Nodes2.begin();
            while (it != Nodes2.end()) {
                if (ip == it->second.ip.substr(0 , ip.length())){

                    vector<string> syncqueuereq;
                    //cout<<endl<<"debug matchMinQueue() "<<matchMinQueue()<<endl;
                   // cout<<"BlAntIsMatch: "<<BlAntIsMatch<<endl;

                    if(!postRefactRoundInit){
                        return crow::response("RefactorizingLastBl"); 
                    }

                    unique_lock<mutex> blkQueuemtxlock(blkQueuemtx);

                    if(blksOPSyncQueue.size()<1){
                        return crow::response("Node Matchmin is syncing"); 
                    }

                   unique_lock<mutex> queuReqmtxlock(queuReqmtx);

                    if( (matchMinQueue() == publicDirNode || BlAntIsMatch) ){

                        queuReq++;
                        auto x = crow::json::load(req.body);

                        if (!x){return  crow::response(""); }
                        uint x1= hexToUint(x["x1"].s());
                        uint x2= hexToUint(x["x2"].s());
                        string x3= x["x3"].s();

                        if(x1<0 || x2 > blksOPSyncQueue.size()-1  || x3.length() !=64 ){
                            queuReq--;
                            return  crow::response(""); 
                        }

                        uint64_t  nodelbi = Nodes2[it->first].lastblLocal;     
                        uint64_t lbl = lastblockbuilt();   

                        if( nodelbi == lbl&& !BlAntIsMatch){

                            cout<<endl<<"queue call cond nodelbi == lbl && !BlAntIsMatch "<<endl;

                            if(x2==0){ x2 = blksOPSyncQueue.size()-1; }

                            cout<<endl<<"x1 "<<x1<<" x2 "<<x2<<endl;

                            for(x1;x1<=x2;x1++){ 
                                syncqueuereq.push_back(blksOPSyncQueue[x1]); 
                            }

                            if(syncqueuereq.size()<1){
                                queuReq--;
                                return crow::response("syncedToLastOp"); 
                            }

                            string to_firm = "";
                            uint syncqueuesize = syncqueuereq.size();

                            for(int i =0; i< syncqueuesize; i++){
                                to_firm+= syncqueuereq[i];
                            }

                            string signature = LocalSigner(x3+to_firm);
                           // cout<<"debug queue to firm "<<to_firm<<endl;
                            //cout<<"debug queue signature"<<signature<<endl;

                            syncqueuereq.push_back(signature);

                            crow::json::wvalue response;
                            response = syncqueuereq;
                            queuReq--;
                            return crow::response(response); 

                        }

                        if( nodelbi == lbl&& BlAntIsMatch){

                            cout<<endl<<"queue call cond nodelbi == lbl && BlAntIsMatch "<<endl;

                            if(x2==0){ x2 = blksOPSyncQueue.size()-1; } else{x2 +=lastmatchsyncqueue; }

                            x1+=lastmatchsyncqueue;

                            for(x1;x1<=x2;x1++){ 
                                syncqueuereq.push_back(blksOPSyncQueue[x1]); 
                            }
                            if(syncqueuereq.size()<1){
                                queuReq--;
                                return crow::response("syncedToLastOp"); 
                            }

                            string to_firm;
                            int syncqueuesize = syncqueuereq.size();

                            for(uint i =0; i< syncqueuesize; i++){
                                to_firm+= syncqueuereq[i];
                            }

                            syncqueuereq.push_back(LocalSigner(x3+to_firm));
                            crow::json::wvalue response;
                            response = syncqueuereq;
                            queuReq--;
                            return crow::response(response); 
                            
                        }

                        if( nodelbi == lbl-1&& BlAntIsMatch){

                            if(x2==0){ x2 = blksOPSyncQueue.size()-1; }

                            cout<<endl<<"queue call cond nodelbi == lbl-1&& BlAntIsMatch "<<endl;

                            for(x1 ;x1<lastmatchsyncqueue; x1++){ 
                                syncqueuereq.push_back(blksOPSyncQueue[x1]); 
                            }

                            if(syncqueuereq.size()<1){
                                queuReq--;
                                return crow::response("syncedToLastOp"); 
                            }

                            string to_firm;
                            int syncqueuesize = syncqueuereq.size();

                            for(int i =0; i< syncqueuesize; i++){to_firm+= syncqueuereq[i];}

                            cout<<endl<<"queue call cond nodelbi == lbl-1&& BlAntIsMatch to_firm "<<to_firm<<endl;

                            syncqueuereq.push_back(LocalSigner(x3+to_firm));

                            crow::json::wvalue response;
                            response = syncqueuereq;
                            queuReq--;
                            return crow::response(response); 
                            
                        }
                    
                        queuReq--;

                    } 

                    cout<<endl<<"debug call queue  blksOPSyncQueue matchMinQueue() != publicDirNod "<< endl;

                    string shalbbb = shaLBB();
                    syncqueuereq.push_back(shalbbb);

                    syncqueuereq.push_back(LocalSigner(shalbbb));

                    crow::json::wvalue response;
                    response = syncqueuereq;
                    return crow::response(response); 

                }
            ++it;
            }

            string requi= req.body;
            cout<<endl<<"Unnautorized_Call: "<< ip << requi <<endl;
           return crow::response( "Unnautorized_Call"); 

        }

        return crow::response( fw); 

    });
    CROW_ROUTE(app, "/lastblsync").methods("POST"_method)([](const crow::request &req, crow::response &res){

        string fw=firewall(req.remote_ip_address, "syncTransacAlg");
        if( fw == "true"){
            if (Loggednode(req.remote_ip_address)){

                auto x = crow::json::load(req.body);
                res.set_header("Content-Type", "text/plain");
                if (!x) {
                    res.body = "Invalid Format Request";
                    return res.end();
                }

                string data = x["x1"].s();
                string sign = x["x2"].s();
                int clientTiming=stoi(data.substr(80 , 10));
                int localtimestg= stoi(timing());

                if(data.length()!=90 ||sign.length()!=128|| localtimestg>clientTiming+300 ||localtimestg<clientTiming-300||!HexCheck(data)  ){
                    res.body = "data transaction is invalid";
                    return res.end();
                }

                string ipdir = ipDir(req.remote_ip_address);
                cout<<endl<<"debug  call lastblsync ipdir "<<ipdir<<endl;

                if( !verifySignature(data,  sign,  loadPublicKey(ipdir.substr(2,128)))){
                    cout<<endl<<"Invalid Signature req : "<<req.remote_ip_address<<" call to : /lastblsync ";
                    res.body = "Invalid Signature req";
                    return res.end();
                }

                unique_lock<mutex> peerssyncblocklock(peerssyncblock);
                Nodes[ipdir].lastblLocal = hexToULL(data.substr(0,16));
                res.body = "STATUS_OK";
                return res.end();
                }
            }
            
        res.body = fw;
        return res.end(); 
    }); 
    CROW_ROUTE(app, "/queueErased").methods("POST"_method)([](const crow::request &req, crow::response &res){
        
       // cout<<endl<<"<======= call req /queueErased"<<endl;

        res.set_header("Content-Type", "text/plain");
        string fw=firewall(req.remote_ip_address, "syncTransacAlg");
        if( fw == "true"){
            if (BlAntIsMatch ){
                res.body = ":)";
            } else{res.body = ":(";}
            return res.end();
        }
        res.body = fw;
        return res.end(); 
    });  
    CROW_ROUTE(app, "/blockdl").methods("POST"_method)([](const crow::request &req){

        string fw=firewall(req.remote_ip_address, "blocksearch");

        cout<<endl<<" request blockdl"<<endl;

        if( fw == "true"&& Loggednode(req.remote_ip_address)){

            cout<<endl<<" request blockdl pass firewall"<<endl;

            auto x = crow::json::load(req.body);

            if (!x){
                cout<<endl<<" request blockdl !x "<<req.body<<endl;
                return crow::response("wrong format query !x"); 
            }

            if(!HexCheck(x["x1"].s())&&!HexCheck(x["x2"].s())&&!HexCheck(x["x3"].s()) ){
                return crow::response("wrong format query !HexCheck"); 
            }

            uint x1= hexToUint(x["x1"].s());
            uint64_t x2= hexToUint(x["x2"].s());
            string x3= x["x3"].s();

            if(x2 > lastbl || x3.length() != 64 ){
                return crow::response("number Bl request > LastBlLocal || x3.length() != 64"); 
            }

            vector<string> ResJsonData;

            cout<<endl<<" request blockdl x1 =  "<<x1<<endl;

            if (x1 == 0){

                cout<<endl<<" dl bl request debug  0 " << ShaBlB2(x2)<< endl;
                ResJsonData.push_back( ShaBlB2(x2) +x3);
                ResJsonData.push_back(LocalSigner(ResJsonData[0]));
                crow::json::wvalue response;
                response = ResJsonData;
                return crow::response(response); 
                
            }

            if (x1 == 1){

                cout<<endl<<" request blockdl x1 =  1  x2 ="<<x2<<endl;

                ResJsonData.push_back(blreadblocksearch(to_string(x2))+x3);
                ResJsonData.push_back(LocalSigner(ResJsonData[0]));
                crow::json::wvalue response;
                response = ResJsonData;

                cout<<endl<<" request blockdl x1 =  1  end req fl"<<ResJsonData[0]<<endl;
                return crow::response(response); 
            }

            return crow::response("error request");

            }

        return crow::response(fw);
    });

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Front User serve html/js & misc
    // 

    CROW_ROUTE(app, "/")([](const crow::request &req){ 
        string fw=firewall(req.remote_ip_address, "front");
        if( fw == "true"){
            if((OnlyLocalApi &&req.remote_ip_address=="127.0.0.1")||!OnlyLocalApi){
                auto page = crow::mustache::load("index.html");
                crow::mustache::context ctx;
                ctx["shaLBB"] =shaLBB();
                return page.render(ctx);
            }
            auto page = crow::mustache::load(NULL);
            crow::mustache::context ctx;
            return page.render(ctx);
        }
        auto page = crow::mustache::load("Error.html");
        crow::mustache::context ctx;
        ctx["Error"] =fw;
        return page.render(ctx);
    });
    CROW_ROUTE(app, "/derivat")([](const crow::request &req){
        string fw=firewall(req.remote_ip_address, "front");
        if( fw == "true"){ 
            auto page = crow::mustache::load("derivat.html");
            return page.render(); 
        } 
        auto page = crow::mustache::load("Error.html");
        crow::mustache::context ctx;
        ctx["Error"] =fw;
        return page.render(ctx);
    });
    CROW_ROUTE(app, "/consul")([](const crow::request &req){ 
        

        string fw=firewall(req.remote_ip_address, "front");
        if( fw == "true"){ 
            auto page = crow::mustache::load("consulta.html");
            return page.render(); 
        } 
        auto page = crow::mustache::load("Error.html");
        crow::mustache::context ctx;
        ctx["Error"] =fw;
        return page.render(ctx);
    });
    CROW_ROUTE(app, "/info")([](const crow::request &req) {


        string fw=firewall(req.remote_ip_address, "front");
        if( fw == "true"){ 
            auto page = crow::mustache::load("info.html");
            return page.render(); 
        } 
        auto page = crow::mustache::load("Error.html");
        crow::mustache::context ctx;
        ctx["Error"] =fw;
        return page.render(ctx);
    });
    CROW_ROUTE(app, "/bloque")([](const crow::request &req){

        string fw=firewall(req.remote_ip_address, "front");
        if( fw == "true"){ 
            auto page = crow::mustache::load("bloque.html");
            return page.render(); 
        } 
        auto page = crow::mustache::load("Error.html");
        crow::mustache::context ctx;
        ctx["Error"] =fw;
        return page.render(ctx);
    });
    CROW_ROUTE(app, "/requestjson.js")([](const crow::request &req){
        string fw=firewall(req.remote_ip_address, "front");
        crow::response res;
      
        if( fw == "true"){ 
            ifstream file("templates/requestjson.js");
            if (file.is_open()) {
            stringstream buffer;
            buffer << file.rdbuf();
            file.close();
            res.add_header("Content-Type", "application/javascript");

            res.write(buffer.str());
            } else {
            res.code = 500; 
            res.write("Error al cargar el archivo JavaScript");
            }

            return res;

        } 
        res.write(fw);
        return res; 

    });
    CROW_ROUTE(app, "/css.css")([](const crow::request &req){
        
        string fw=firewall(req.remote_ip_address, "front");
        if( fw == "true"){ 
            crow::mustache::context ctx;
            return crow::mustache::load_text("css.css");
        } 
        crow::mustache::context ctx;
        return crow::mustache::load_text(fw);
    });
    CROW_ROUTE(app, "/signer2.js")([](const crow::request &req){
        
        string fw=firewall(req.remote_ip_address, "front");
        if( fw == "true"){ 
            crow::mustache::context ctx;
            return crow::mustache::load_text("signer2.js");
        } 
        crow::mustache::context ctx;
        return crow::mustache::load_text(fw);
        
    });
    CROW_ROUTE(app, "/status.js")([](const crow::request &req){
        
        string fw=firewall(req.remote_ip_address, "front");
        if( fw == "true"){ 
            crow::mustache::context ctx;
            return crow::mustache::load_text("status.js");
        } 
        crow::mustache::context ctx;
        return crow::mustache::load_text(fw);
    });

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // request api
    // data index

    CROW_ROUTE(app, "/balance").methods("POST"_method)([](const crow::request &req, crow::response &res){

        string fw=firewall(req.remote_ip_address, "blocksearch");

        if( fw == "true"){

            res.body = fw;
            auto x = crow::json::load(req.body);
            if (!x){
                res.set_header("Content-Type", "text/plain");
                res.body = "Bad Format";
                return res.end();
            }
            if (Refactorizing) {
                res.body = "Refactorizing new block please wait";
                res.set_header("Content-Type", "text/plain");
                res.end();
            }
            res.set_header("Content-Type", "text/plain");
            string account = x["resource"].s();
            for (auto &s : account){s = toupper(s);}
            string response=searchlastmove( account,false);

            if(!HexCheck(response)){
                res.body = "Error "+response;
                cout<<endl<< response<<endl;
            }else{
            res.body = response;
            }
        }

        return res.end(); 

    });

    CROW_ROUTE(app, "/blocksearch").methods("POST"_method)([](const crow::request &req, crow::response &res){

        string fw=firewall(req.remote_ip_address, "blocksearch");

        if( fw == "true"){

            res.set_header("Content-Type", "text/plain");
            auto x = crow::json::load(req.body);

            if (!x){
                res.body = "Bad Format";
                return res.end();
            }

            if(!HexCheck(x["resource"].s())){
                res.body = "Bad Format";
                return res.end();
            }

            if (x["resource"].s() == ""){
                res.body = blreadblocksearch(to_string(lastbl));
                return res.end();
            }

            res.body = blreadblocksearch(x["resource"].s());
            return res.end();
            }
        res.body = fw;
        return res.end(); 
    });
    CROW_ROUTE(app, "/IndexTransaction").methods("POST"_method)([](const crow::request &req, crow::response &res){

        string fw=firewall(req.remote_ip_address, "blocksearch");

        if( fw == "true"){

            res.set_header("Content-Type", "text/plain");
            auto x = crow::json::load(req.body);

            if (!x){
                res.body = "Bad Format";
                return res.end();
            }

            string typeIndex = x["typeIndex"].s();


            if ( hexToInt(typeIndex) == 0){
                string valueA = x["valueA"].s();
                string valueB= x["valueB"].s();
                res.body =  transacByNumer2( hexToULL(valueA) , hexToInt(valueB) );
            }
            if ( hexToInt(typeIndex) == 1){
                string valueA = x["valueA"].s();
                string valueB= x["valueB"].s();
                res.body = transacIdHash2( hexToULL(valueA) , hexToInt(valueB));
            }

            if ( hexToInt(typeIndex) == 2){
                string valueC= x["valueC"].s();
                res.body = searchtransac( valueC );
            }

            if ( hexToInt(typeIndex) == 3){

                string valueA = x["valueA"].s();
                string valueB= x["valueB"].s();

                cout<<endl<<" valueA "<<hexToULL(valueA)<< " valueA "<<hexToULL(valueB)<<endl;

                res.body =  MsgTransacbynunmbr( hexToULL(valueA) ,hexToInt(valueB));
            }

            return res.end();
            }

        res.body = fw;
        return res.end(); 
    });
    //120  x min 
    CROW_ROUTE(app, "/status").methods("GET"_method)([](const crow::request &req){

            string fw=firewall(req.remote_ip_address, "status");
            if( fw == "true"){

                vector<string> fl;
                if(synced&&matchminRounInit){
                    if(Refactorizing){
                        fl.push_back("Refactorizing...");
                    } else{
                        fl.push_back("synced");
                    }
                } else {
                    if(syncing){
                        fl.push_back("syncing...");
                    }
                    fl.push_back("unsynced");
                }
                fl.push_back( to_string(transacsconfirmed) );
                fl.push_back( to_string(blksize) );
                fl.push_back( to_string(lastblockbuilt()) );
                fl.push_back( to_string( lastblDWULL));
                fl.push_back( shaLBB());

                crow::json::wvalue response;
                response = fl;
                return crow::response(response); 
            }

        return crow::response(fw); 
    });
    CROW_ROUTE(app, "/Refact").methods("POST"_method)([](const crow::request &req, crow::response &res){

        if(req.remote_ip_address == "127.0.0.1"){
            auto x = crow::json::load(req.body);

            if (!x){
                res.set_header("Content-Type", "text/plain");
                res.body = "Bad Format";
                return res.end();
            }
            res.set_header("Content-Type", "text/plain");
            res.body = refactvalidate();
            return res.end(); 
        }

        cout<<endl<<" Req-res "<<req.remote_ip_address;
        cout << endl<< "Reject unauthorized call " << endl;
        res.body = "Unauthorized call";
        return res.end(); 

    });

    CROW_ROUTE(app, "/blks").methods("POST"_method)([](const crow::request &req, crow::response &res){

        if(req.remote_ip_address == "127.0.0.1"){

            res.set_header("Content-Type", "text/plain");
            auto x = crow::json::load(req.body);
            if (!x){
                res.body = "Bad Format";
                return res.end();
            }
            res.body =  blksOP[x["x"].i()];

            cout<<endl<<"blksOP["<<x["x"].i()<<"] :" << res.body <<endl;
            return res.end();
        }
        cout<<endl<<" Req-res "<<req.remote_ip_address;
        cout << endl<< "Reject unauthorized call " << endl;
        res.body = "Unauthorized call";
        return res.end(); 
    });
    CROW_ROUTE(app, "/maxtrxbl").methods("GET"_method)([](const crow::request &req, crow::response &res){
        if(req.remote_ip_address == "127.0.0.1"){
            res.set_header("Content-Type", "text/plain");
            res.body = ullToHex(maxblks());
            cout<<endl<<"maxtrxbl "<< res.body;
            return res.end();
        }
        cout<<endl<<" Req-res "<<req.remote_ip_address;
        cout << endl<< "Reject unauthorized call " << endl;
        res.body = "Unauthorized call";
        return res.end(); 
    });
    CROW_ROUTE(app, "/shaLBB").methods("GET"_method,"POST"_method)([](const crow::request &req, crow::response &res){
        
        if(!synced){
            res.set_header("Content-Type", "text/plain");
            res.body = "syncing network";
            return res.end();

        }
        
        res.set_header("Content-Type", "text/plain");
        res.body = shaLBB();
        return res.end();
        
        cout<<endl<<" Req-res "<<req.remote_ip_address;
        cout << endl<< "Reject unauthorized call " << endl;
        res.body = "Unauthorized call";
        return res.end(); 
    });
    CROW_ROUTE(app, "/MatchMin").methods("GET"_method)([](const crow::request &req, crow::response &res){
        
        if(req.remote_ip_address == "127.0.0.1"){
            res.body = matchminsorted;
            return res.end();
        }
        cout<<endl<<"Req ip : "<<req.remote_ip_address;
        cout << endl<< "Reject unauthorized call " << endl;
        res.body = "Unauthorized call";
        return res.end(); 
    });

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                           
                            // admin - only local served


    crow::SimpleApp app2;

    CROW_ROUTE(app2, "/nodeset").methods("GET"_method)([](const crow::request &req){

        if(req.remote_ip_address == "127.0.0.1"){
            auto page = crow::mustache::load("nodeset.html");
            crow::mustache::context ctx;
            ctx["idblockchainName"] = idblockchainName;
            ctx["dir_feeds"] = dir_feeds;
            ctx["feeds_ratio"] = feeds_ratio;
            ctx["person"] = publicDirNode;
            ctx["blksize"] = blksize;
            ctx["transacmaxtime"] =transacmaxtime;
            ctx["port"] =port;
            ctx["shablbmaxbuffer"] =shablbmaxbuffer;
            ctx["accIndexMaxCache"] =accIndexMaxCache;
            ctx["Maxtimingbl"] = Maxtimingbl;
            return page.render(ctx);
        }

        auto page = crow::mustache::load("Unauthorized");
        crow::mustache::context ctx;
        return page.render(ctx);
           
     
    });
    CROW_ROUTE(app2, "/NodesDir").methods("GET"_method)([](const crow::request &req){
        
        if(req.remote_ip_address == "127.0.0.1"){
            crow::json::wvalue response;
            unique_lock<mutex> peerssyncblocklock(peerssyncblock);
            vector<string> fl = PublicNodesDir2();
            response = fl;
            return crow::response(response); 
        }
        return crow::response("") ;
    });
    CROW_ROUTE(app2, "/reqnode.js")([](const crow::request &req){
        if(req.remote_ip_address == "127.0.0.1"){
            crow::mustache::context ctx;
            return crow::mustache::load_text("reqnode.js"); 
        }
        return crow::mustache::load_text(""); 
    });
    CROW_ROUTE(app2, "/SetAdm").methods("POST"_method)([](const crow::request &req, crow::response &res){

        if(req.remote_ip_address == "127.0.0.1"){

            res.set_header("Content-Type", "text/plain");
            auto x = crow::json::load(req.body);
            if (!x){
                res.body = "Bad Format";
                return res.end();
            }

            if (x["o"].i() == 1){

                if(setmaxblks(x["resource"].i())){
                   // blksize =x["resource"].i();
                    res.body = "OK";
                    return res.end(); 
                }
            }

            if (x["o"].i() == 2){

                if(setmaxclientresp(x["resource"].i())){
                    transacmaxtime = x["resource"].i();
                    res.body = "OK";
                    return res.end(); 
                }
            }

            if (x["o"].i() == 3){

                if(portsetting(x["resource"].i())){
                    port = x["resource"].i();
                    res.body = "OK";
                    return res.end(); 
                }
            }

            if (x["o"].i() == 4){

                if(feedToDirsetting(x["resource"].s())){
                    res.body = "OK";
                    return res.end(); 
                }
            }

            if (x["o"].i() == 5){
                if(feedRatiosetting(x["resource"].i())){
                    feeds_ratio = x["resource"].i();
                    res.body = "OK";
                    return res.end(); 
                }
            }

            if (x["o"].i() == 6){
                if(shablbmaxbuffersetting(x["resource"].i())){
                    shablbmaxbuffer = x["resource"].i();
                    res.body = "OK";
                    return res.end(); 
                }
            }

            if (x["o"].i() == 7){
                if(accIndexMaxCachesetting(x["resource"].i())){
                    accIndexMaxCache = x["resource"].i();
                    res.body = "OK";
                    return res.end(); 
                }
            }

            if (x["o"].i() == 8){
                if(SetTimingBl(x["resource"].i())){
                    Maxtimingbl = x["resource"].i();
                    res.body = "OK";
                    return res.end(); 
                }
            }

            cout<<endl<<" error req: "<<x["o"].i();

        }

        cout<<endl<<" Req-res "<<req.remote_ip_address;
        cout << endl<< "Reject unauthorized call " << endl;
        res.body = "Unauthorized call";
        return res.end(); 

    });
    CROW_ROUTE(app2, "/css.css")([](const crow::request &req){
        
        crow::mustache::context ctx;
        return crow::mustache::load_text("css.css");
        
    });

    CROW_ROUTE(app2, "/paire").methods("POST"_method)([](const crow::request &req, crow::response &res){

        if (req.remote_ip_address=="127.0.0.1"){

            res.set_header("Content-Type", "text/plain");
            auto x = crow::json::load(req.body);
            if (!x) {res.body = "Bad Format";  return res.end();}
            string PublicAddress = x["PublicAddress"].s();
            for (auto &acc : PublicAddress) { acc = toupper(acc);}
            filesystem::path directory = "peer/PublicNode/";
            for (const auto &entry : filesystem::directory_iterator(directory)){
                if (entry.is_regular_file()) {
                    string PublicNodeDB = entry.path().filename().string();
                    if (PublicNodeDB == PublicAddress){

                        //TIMING
                        string localtimestg = timing();
                        string LastBlSHA = shaLBB();
                        string msg = SHAstg(publicDirNode)+"00"+SHAstg(PublicAddress)+"00"+LastBlSHA+"00"+localtimestg;
                        string sig = LocalSigner(msg);
                        msg = msg + "00" + sig;

                        if (!verifySignature(msg.substr(0, 208), sig, loadPublicKey(publicDirNode.substr(2, 128)))){
                            res.body = "signing_Error";
                            return res.end();
                        }

                        string ip = x["ip"].s();

                        string stresponse = curlpost2("https://" + ip + "/pair", msg, timeout_ms);

                        if(stresponse.length()!= 210){
                            cout<<endl<<"invalid response"<<endl;
                        }

                        if (!verifySignature(SHAstg(PublicAddress)+"00"+SHAstg(publicDirNode)+"00"+LastBlSHA+"00"+localtimestg, stresponse.substr(210, 128), loadPublicKey(PublicAddress.substr(2, 128)))){
                            cout << "Invalid Signature" << endl;
                            cout << msg.substr(130,64)+"00"+msg.substr(0,64)+"00"+LastBlSHA+"00"+localtimestg+" signature "+stresponse.substr(340, 128)<<endl;
                            cout<<endl<<"stresponse "<<stresponse<<endl;
                        }

                        vector<uint8_t> byteArray = stringToBytes(stresponse);
                        if (!loginPeer(stresponse, ip )){res.body = "Loggin_Error";
                            return res.end();
                        }

                        ofstream filew("peer/" + ip , ios::binary | ios::out);
                        if (!filew){ cout << "error al abrir la Db de dirs"; return res.end();  }

                        for (unsigned int i = 0; i < byteArray.size(); i++){
                            filew.seekp(i);
                            filew.put(byteArray[i]);
                        }
                        filew.close();
                        string stringread = bytesToString(readFile("peer/" + ip ));
                        res.body = stringread;
                        return res.end();
                    }
                }
            }
        cout<<endl<<"Unnautorized_Call:Paire";
        res.body = "Unautorized_Call";
        return res.end();
        }
    
        cout<<endl<<"Ignorando Req-res "<<req.remote_ip_address<<endl;
        cout << endl<< "Unauthorized call " << endl;
        res.body = "Unauthorized call";
        return res.end(); 

    }
    );
    CROW_ROUTE(app2, "/NodesNetworkSet").methods("POST"_method)([](const crow::request &req, crow::response &res){

        cout<<endl<<" NodesNetworkSet call"<<endl;

        if (req.remote_ip_address=="127.0.0.1"){

            try {

                auto x = crow::json::load(req.body);
                string ApiQuery = x["x1"].s();

                cout<<endl<<" debug apiquery call " <<ApiQuery<<endl;

                if(ApiQuery == "SaveNode" ){

                    string PublicAddress= x["x2"].s();
                    if(!HexCheck(PublicAddress) ||  PublicAddress.length() != 130 ){
                        res.body = "Error Saving new Address, invalid format ";
                        return res.end();
                    }
                    // verificar que la direccion tenga un formato correcto
                    for (auto &acc : PublicAddress) {acc = toupper(acc);}

                    if(!saveNewNode(PublicAddress)){
                        res.body = "Error Saving new Address";
                        return res.end();
                    }

                    res.body = "Success";
                    return res.end(); 

                }

                if(ApiQuery == "EraseNode" ){

                    cout<<endl<<" debug EraseNode call 1" <<ApiQuery<<endl;

                    string PublicAddress= x["x2"].s();

                    if(!HexCheck(PublicAddress) ||  PublicAddress.length() != 130 ){
                        res.body = "invalid format address";
                        cout<<endl<<" invalid format Address"<<endl;
                        return res.end();
                    }

                    for (auto &acc : PublicAddress) {acc = toupper(acc);}

                    cout<<endl<<" debug EraseNode call 2" <<ApiQuery<<endl;

                    if(!EraseNode(PublicAddress)){
                        res.body = "Error erasing Address";
                        cout<<endl<<" Error erasing Address"<<endl;
                        return res.end();
                    }
                    cout<<endl<<"Node deleted: "<<PublicAddress<<endl;
                    res.body = "Success";
                    return res.end(); 

                }

                if(ApiQuery == "PaireNode" ){

                    string PublicAddress= x["x2"].s();
                    string IpAddress= x["x3"].s();

                    cout<<endl<<"debug paire node ip "<<IpAddress;

                    string result =  paireNode(PublicAddress, IpAddress ); 

                    res.body = result;
                    return res.end(); 

                }

            } catch (const exception& e)  {

            }

        }

    });
    CROW_ROUTE(app2, "/LastBlVD").methods("GET"_method)([](const crow::request &req, crow::response &res){
        res.body = to_string(hexToULL(lastblDW().substr(0,8)));
        return res.end(); 
    });
    CROW_ROUTE(app2, "/PeersLogged").methods("GET"_method)([](const crow::request &req, crow::response &res){
        res.set_header("Content-Type", "text/plain");
        res.body = to_string(PeersLogged());
        return res.end();
    });
    CROW_ROUTE(app, "/MakeWallet").methods("POST"_method)([](const crow::request &req, crow::response &res)
                                {
                                    auto x = crow::json::load(req.body);

                                    if (!x)
                                    {
                                        res.body = "Bad Format";
                                        return res.end();
                                    }

                                    res.set_header("Content-Type", "text/plain");
                                    string account = x["resource"].s();
                                    memset(&x, 0, sizeof(x));
                                    string stg = derivate(account);
                                    stg = stg.substr(2, 128);
                                    cout<<stg;
                                    res.body = stg;

    return res.end(); 
    });


    app.loglevel(crow::LogLevel::Warning);
    auto _a = app.port(port).ssl_file("ssl/domain.crt", "ssl/domain.key").concurrency(4).run_async();
    auto _b=  app2.port(19080).multithreaded().run_async();

    return 0;
}

int main(){

    instanceElementsTransaction();

    //Hash LastBlock;
    shaLBBArr();
    
    //purge bad/wrong download blocks
    for (const auto &entry : filesystem::directory_iterator("blocks/dlsync")){
        if (entry.is_regular_file()){
            try {
                filesystem::remove("blocks/"+entry.path().filename().string());
            } catch (const exception& e) {
            }
            remove(entry);
        }
    }

    for (int i = 0;i<256;i++){ 
        F256+="F"; 
    }

    for (auto &s : dir_feeds){
        s = toupper(s);
    }

    cout<<endl<<" checking blocks DB integrity...";
    
    
    for(uint64_t i = lastbl, e = 0; i>0; i--){
        cout << "\033[2J\033[1;1H";
        cout<<endl<<" checking block: "<<to_string(i)<<" %"<< ((e*10)/lastbl)*10;
        e++;
        if(build_uncompressbl_secuCheck(i).size()<213){
            exit_call();
        }
    }

    ifstream archivo2("node/priv");
    if (archivo2.is_open()){
        string pr;
        getline(archivo2, pr);
        archivo2.close();
        publicDirNode = derivate(pr);
        pr="";
    }

    cout<<endl<<endl<<endl<<endl<<endl<<endl<<endl;
          cout<<"#################################################################################################"; 
    cout<<      "                                                                                                 " << endl;
    cout<<endl<<"                                                |                        Δ                       |" << endl;                            
    cout<<      "                                                |                       * *                      |" << endl;
    cout<<      "             ***~ CryptoDbSS ~***               |          MatcMin     *   *         ALL         |" << endl;                                                    
    cout<<      "                                                |                     *     *                    |" << endl;    
    cout<<      "                                                |                    *       *                   |" << endl;
    cout<<      "      Blockchain-core scheme, Consensus,        |    @  *  *  *  *  *  *   *  *  *  *  *  *  @   |" << endl;         
    cout<<      "             Protocols and misc.                |      *           * ######### *           *     |" << endl;             
    cout<<      "                                                |         *       * ########### *       *        |" << endl;
    cout<<      "                                                |            *   * ############# *   *           |" << endl;
    cout<<      "                 Validator Node                 |               * ############### *              |" << endl;
    cout<<      "                                                |              *   * ######### *   *             |" << endl;
    cout<<      "        this software is developing by:         |       ARE   *       * ### *       *    ONE     |" << endl;
    cout<<      "                                                |            *           *           *           |" << endl;
    cout<<      "  Steeven Salazar || Steevenjavier@gmail.com    |           *   _    *       *    _   *          |" << endl;
    cout<<      "                                                |          @            S.S            @         |" << endl;
    cout<<      "                                                                                              " << endl;
    cout<<      "#################################################################################################" << endl;  
    cout<<      "                                                                                             " << endl;
    cout<<      "Blockchain:                 " << idblockchainName<< endl; 
    cout<<      "Blockchain Id:              " <<  idBlckchn<< endl<<endl;           
    cout<<      "Node Address:             " << publicDirNode.substr(0, 66)<< endl<< 
                "                            "+publicDirNode.substr(66, 64)<<endl<<endl;   
    cout<<      "Address feed receiver:      "<<dir_feeds.substr(0, 64)<< endl<< 
                "                            "+dir_feeds.substr(64, 64)<<endl<<endl;    
    cout<<      "last local block built:           " << lastbl<<endl; 
    cout<<      "version:                    " << version<< endl<<endl;   
    
    cout<<      "#################################################################################################" << endl;                        

    
    cout<<endl<<endl<<"DB integrity OK";
    

    
    ClearOpBlks();

    peersLogin();

    syncNetwork();

    cout<<endl<<"init threads..";

    /////////////////////////////////////threads init//////////////////////

    thread thread3(syncnetwork_lastblock);
    thread3.detach();

    thread thread2(firewallCountTime);
    thread2.detach();

    thread thread6(AliveConnection);
    thread6.detach();

    thread thread1(comfirmOptrancasync);
    thread1.detach();

    thread thread5(timetransacthread);
    thread5.detach();
          
    thread thread7(statusCheck);
    thread7.detach();

    this_thread::sleep_for(chrono::seconds(4));

    thread thread4(syncnetwork_matchMinRound);
    thread4.detach();
     
    //////////////////////////////////////////////////////////////////////////////////

    // run network server
    listener();

    return 0;
}

#endif

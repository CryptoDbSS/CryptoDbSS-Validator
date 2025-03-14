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

#include "CryptoDbSS.cpp"

extern bool OnlyLocalApi;
extern bool synced;
extern bool matchminRounInit ;
extern bool postRefactRoundInit;
extern mutex queueIpMtx;
extern vector <string> queueIp;
extern mutex MatchminTransacsmtx;

bool GetDataTransacFilterData0x00(string &reqJsonData, string &res){

    auto x = crow::json::load(reqJsonData);

    string TransactionType = x["v"].s();
    string From = x["w"].s();
    string To = x["x"].s();
    string value = x["y"].s();
    string sign = x["z"].s();

    if(From.length()!=130 ||To.substr(0, 2) != "04"|| From.substr(0, 2) != "04"|| To.length()!=130 ||value.length()!=16||sign.length()!=128||!HexCheck(From)||!HexCheck(To) || !HexCheck(value) ||!HexCheck(sign)  ){
        res = "data transac invalid";
        return false;
    }

    if( !verifySignature( shaLBB()+TransactionType+From+To+value,  sign ,  loadPublicKey(From.substr(2 , 128))) ){
        res =  "Invalid sign from user! ";
        return false;
    }

    return true;

}

bool GetDataTransacFilterData0x0A(string &reqJsonData, string &res){

    auto x = crow::json::load(reqJsonData);
    string TransactionType = x["v"].s();
    string From = x["w"].s();
    string Msg32 = x["x"].s();
    string value = x["y"].s();
    string sign = x["z"].s();

    if(From.length()!=130 ||Msg32.length()!=64 ||value.length()!=16||sign.length()!=128||!HexCheck(From)|!HexCheck(value)|!HexCheck(sign) || !HexCheck(Msg32)  ){

        cout<<endl<<" fl "<< From.length()<<"  "<<Msg32.length()<<"  "<<value.length()<<"  "<<sign.length();
        res = "data transaction req invalid";
        return false;
    }

    if( !verifySignature( shaLBB()+TransactionType+From+Msg32+value,  sign ,  loadPublicKey(From.substr(2 , 128))) ){
        res =  "Invalid sign from req! ";
        return false;
    }

    return true;

}

bool GetDataTransacFilterData(string &reqJsonData, string &res){

    auto x = crow::json::load(reqJsonData);
    string TransactionType = x["v"].s();
    uint8_t TransactionTypeUint8 = hexToUint8_t(TransactionType);

    switch(TransactionTypeUint8 ){

        case 0x00 :
            return GetDataTransacFilterData0x00(reqJsonData , res);
            break;

        case 0x0A :
        case 0x0C :
            return GetDataTransacFilterData0x0A(reqJsonData , res);
            break;

        default:
            return false;
            break;
    }

    return false;

}

string GetDataTransac(string req, string req_Ip ){

    string res = "";
    cout<<endl<<"Transaction requested ";

    if((OnlyLocalApi &&req_Ip=="127.0.0.1")||!OnlyLocalApi){


        if(!synced||!matchminRounInit||!postRefactRoundInit){
            cout<<endl<<"the node is preparing to build a new block,.";
            return "wait a moment while the node is preparing to build the block and try again.";
        }

        if (!GetDataTransacFilterData(req , res)){
            return res;
        }

        if (Refactorizing) {
            return  "Refactorizing new block please wait a moment and try again";
        }

        std::unique_lock<std::mutex> pricesingtransacCountlock(pricesingtransacCount);
        pretransacpending++;

        if ( pretransacpending + transacpendingcount + transacsconfirmed >blksize) {
            pretransacpending--;
            return "please wait a moment and try again";
        }

        pricesingtransacCountlock.unlock();
        string queuetransac = random32Hex(); 

        std::unique_lock<std::mutex> queuetransacsmtxlock(queuetransacsmtx);
        queuetransacs[queuetransac] = "processing";
        queuetransacsmtxlock.unlock();
        
        res = queuetransac;

        thread getdatatransacthr(getdatatransacthread, queuetransac,  req );

        getdatatransacthr.detach();

        std::unique_lock<std::mutex> queueIpMtxlock(queueIpMtx);
        bool checkip = false;
        for(int i = 0; i<queueIp.size(); i++){
            if(queueIp[i]==req_Ip){
                checkip=true;
            }
        }
        if(!checkip){
            queueIp.push_back(req_Ip);
        }
        
        return res;
    }

    cout<<endl<<"Transaction requested from "<<req_Ip<<" rejected "<< endl;
    return res;


}

string GetDataTransacAuth(string req, string req_Ip ){

    string res = "";

    if( matchMinQueueIp()!="localhost"){
        res = "matchMinQueueIp()!=localhost";
        return res;}

    auto x = crow::json::load(req);

    string jsondataTransac = x[0].s();

    if (!GetDataTransacFilterData(jsondataTransac , res)){
        return res;
    }

    if( !verifySignature(x["x1"].s(), x["x2"].s() ,  loadPublicKey(ipDir(req_Ip).substr(2 , 128))) ){
        
        res = "Invalid signature from node Auth";
        return res;
    }

    if (Refactorizing) {
        res = "Refactorizing new block please wait";
    
        return res;
    }

    if(!synced||!matchminRounInit||!postRefactRoundInit){
        
        res = "syncing network";
        return res;
    }

    std::unique_lock<std::mutex> pricesingtransacCountlock(pricesingtransacCount);
    pretransacpending++;
    
    if ( pretransacpending + transacpendingcount + transacsconfirmed >blksize) {
        pretransacpending--;
        res = "please wait a moment and try again";
    
        return res;
    }

    pricesingtransacCountlock.unlock();
    string queuetransac = random32Hex(); 

    std::unique_lock<std::mutex> queuetransacsmtxlock(queuetransacsmtx);
    queuetransacs[queuetransac] = "processing";
    queuetransacsmtxlock.unlock();
    res = queuetransac;

    thread getdatatransacthr(getdatatransacthread, queuetransac,  jsondataTransac );    
    getdatatransacthr.detach();
    std::unique_lock<std::mutex> queueIpMtxlock(queueIpMtx);
    bool checkip = false;
    for(int i = 0; i<queueIp.size(); i++){
        if(queueIp[i]==req_Ip){
            checkip=true;
        }
    }
    if(!checkip){
        queueIp.push_back(req_Ip);
    }

    return res;

}

string TransacSignedPost(string req, string req_Ip){

    auto x = crow::json::load(req);
    string res = "";

    if(!synced||!matchminRounInit||!postRefactRoundInit){

        return "syncing network";
    }
    if (Refactorizing) {
        return "Refactorizing new block please wait";
    }

    std::unique_lock<std::mutex> pricesingtransacCountlock(pricesingtransacCount);

    if (transacpendingcount>blksize) {
        return "please wait a moment and try again";
    }
    
    pricesingtransacCountlock.unlock();

    if (!x){
        
        return "Format data invalid";
    }
    string straddrs = x["x"].s();
    
    string stg1;
    int savedtimetransactime;

    /*
    cout<<endl<<"transagpost straddrs "<<straddrs.length()<<endl;
    cout<<endl<<"transagpost hexToInt(blOpNmbr(straddrs)) "<<hexToInt(blOpNmbr(straddrs))<<endl;
    cout<<blksOP[hexToInt(blOpNmbr(straddrs))-1]<<endl;

    cout<<endl<<"transagpost witchBlType(blksOP[hexToInt(blOpNmbr(straddrs))-1]) "<<switchBlType(blksOP[hexToInt(blOpNmbr(straddrs))-1])<<endl;
    
    cout<<endl<<"transagpost blksOP[hexToInt(blOpNmbr(straddrs))-1] "<<blksOP[hexToInt(blOpNmbr(straddrs))-1]<<endl;
    cout<<endl<<"transagpost  straddrs.substr(0, 576) "<< straddrs.substr(0, 576)<<endl;
    */

    if (!DataTransactionlengthIsValid ( straddrs )) {
        cout<<endl<<"Data Transaction error, unecpected length: "<<straddrs.length()<<"   "<<straddrs;
        return "DataTransac transacsignedpost - error !length : "+ straddrs;
    }

    string MatchminDir = matchMinQueueIp();

    if( MatchminDir != "localhost"){

        std::unique_lock<std::mutex> MatchminTransacsmtxlock(MatchminTransacsmtx);
        for(uint i = 0 ; i < MatchminTransacs.size() ; i++){
            if(MatchminTransacs[i] == straddrs.substr(0,494)){
                string PairDir;
                PairDir = "https://" +  matchMinQueueIp() + "/TransacSignedPost";
                string response = curlpost2(PairDir, req, 1000);
                if (response.substr(0, 7) == "SUCCESS"){
                    return response;
                } else {
                    return "the transaction from matchmin is fail :( "+response ;
                }
            }
        }

        return "transac not found ";

    } else { 
        if( MatchminDir == "unavailable"){
            return "MatchMin is unavailable ";
        }
    }

    std::unique_lock<std::mutex> writingspacelock(writingspace);

    if( switchBlType(blksOP[hexToInt(blOpNmbr(straddrs))-1]) == DataTransacWithoutSignature(straddrs) && IsTypeConfirmed(bltypeOfString(straddrs) )){     
                
        if ( matchMinQueueIp() == "localhost"){

            savedtimetransactime = transactime[ hexToInt(blOpNmbr(straddrs))-1];
            transactime[ hexToInt(blOpNmbr(straddrs))-1] = 9999;

            if (  blksOP[hexToInt ( blOpNmbr(x["x"].s()))-1] == F256 ){
                transactime[ hexToInt(blOpNmbr(straddrs))-1] = savedtimetransactime;
                return "transac fail or timeout";
            }

            writingspacelock.unlock();
            stg1 =  SignedTransac0002(x["x"].s());
            res = stg1;
            if (stg1.substr(0, 7) == "SUCCESS"){
                return res;
            }

            writingspacelock.lock();
            
            transactime[ hexToInt(blOpNmbr(straddrs))-1] = savedtimetransactime;  

            return res;
        }
        
        else{


        }
    }

    cout<<endl<<"the transaction N "<<hexToInt(blOpNmbr(straddrs))-1<<" could not be validated.";
    //cout<<endl<<blksOP[hexToInt(blOpNmbr(straddrs))-1]<<endl<<endl<<straddrs.substr(0, 494);
    res = "the transaction could not be validated";
    return res;

}
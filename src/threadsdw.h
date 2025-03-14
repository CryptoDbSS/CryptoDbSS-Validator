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

#ifndef THREADSDW_H
#define THREADSDW_H

#include "CryptoDbSS.cpp"

using namespace std;

string refactvalidate();

extern map<string, string> queuetransacs;
extern mutex writingspace;
extern uint16_t blksize;
extern string* blksOP;
extern uint feeds_ratio;
extern string LBBBuffered;
extern string ShaLBBBuffered;
extern time_t* transactime;
extern bool indexingmap;
extern const string idBlckchn;
extern string F256;
extern vector<string>blksOPSyncQueue;
extern mutex blkQueuemtx;
extern int transacmaxtime;
extern vector<string>blksOPSync;
extern map<int,bool>checkTransacSync;
extern map<uint16_t,bool> numberspace;
extern map< array <unsigned char,64>, dbstruct >mapIndex;
extern int32_t transacsconfirmed;
extern bool Refactorizing;
extern mutex WritingAccSync;
extern bool syncing;
extern bool synced;
extern string publicDirNode;
extern bool syncqueue;
extern string dir_feeds;
extern uint syncOpNumbr;
extern int32_t transacpendingcount;
extern string publicDirNode;
extern bool comfirmOptrancasyncRun;
extern bool statusCheckRun;
extern map< array <unsigned char,64>, Accsync >AccSync;
extern vector<string> peersMatchMin;
extern bool peersMatchMinBlock;
extern bool postRefactRoundInit;
extern bool matchminRounInit;
extern int timingRound;
extern unsigned long long lastblDWULL;
extern bool firewallcheck;
extern uint64_t timingbl;
extern uint64_t Maxtimingbl;
extern mutex peerssyncblock;
extern mutex queuetransacsmtx;
extern uint16_t errorMatchminCount;

/**
 * defines the type of transaction by looking to see if the account is in transaction
 */
void getdatatransacthread1 (string &queuetransac, string &DataTransacJson){

    std::unique_lock<std::mutex> queuetransacsmtxlock(queuetransacsmtx);

    auto x = crow::json::load(DataTransacJson);

    if ( matchMinQueueIp() == "localhost"){

        string TransactionType = x["v"].s();
        string cantS = x["y"].s();
        uint8_t TransactionTypeUint8 = hexToUint8_t(TransactionType);
        string stg1 = GetDataTransac( DataTransacJson, TransactionTypeUint8 );

        processAsyncTransac(queuetransac , stg1,  TransactionTypeUint8, hexToUint64(cantS) );

        return;
        
    }

    string sign2 = LocalSigner( DataTransacJson);

    string PairDir = "https://" + matchMinQueueIp() + "/block";
    cout<<endl<<"matchmin "+PairDir<<endl;
    string jsonval = "{\"x1\": \"" + DataTransacJson + "\", \"x2\": \"" + sign2 + "\"}"; 

    string response = curlpost2(PairDir, jsonval, 1000);

        if(response == "00"){
            cout<<endl<<" response error"<<endl;
            queuetransacs[queuetransac] = " response error from matchmin";
            return;
        }

        if (response.length() == 64){

            queuetransacs[queuetransac] = response;

            cout<<endl<<"getdatatransac thr !localhost queuetransacs[queuetransac] definition "<<queuetransacs[queuetransac]<<endl;

            return;
 
        }

    queuetransacs[queuetransac] =  " MatchSHAMin response: fail: " + response;
    return;
        
}

void getdatatransacthread(string queuetransac, string DataTransacJson){

    //cout<<endl<<"getdatatransacthread init ===========>"<<endl;
    getdatatransacthread1 (queuetransac, DataTransacJson);
    //cout<<endl<<"<============  getdatatransacthread end"<<endl;
    extern int32_t pretransacpending;
    std::unique_lock<std::mutex> pricesingtransacCountlock(pricesingtransacCount);
    pretransacpending--;
    return;

}

void syncnetwork_lastblock(){

    while(true){ 
        //cout<<endl<<"syncnetwork init =======>"<<endl;
        if(!syncing&&!Refactorizing){
            syncing = true;
            syncNetwork();
            syncing = false;
        }
        //cout<<endl<<" <==== syncnetwork alg end"<<endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

void comfirmOptrancasync(){

    string bltype;
    string accstrL;
    string accstrR;

    while(true){

       // cout<<endl<<" SynccomfirmOptrancasync init ====>"<<endl;
        if(Refactorizing||Refactoring_internalSecu||!matchminRounInit||!synced){
            std::this_thread::sleep_for(std::chrono::seconds(3));
            continue;
        }

        comfirmOptrancasyncRun = true;

        std::unique_lock<std::mutex> blkQueuemtxlock(blkQueuemtx);

        for(int i = 1; i<=checkTransacSync.size(); i++){

            if(checkTransacSync[i] == false ){

               // cout<<endl<<" SynccomfirmOptrancasync debug blksOPSync "<<i<<" "<<blksOPSync[i]<<endl;

                const uint16_t blopnumb=hexToUint(blksOPSync[i].substr(0,8));

                if(blopnumb>65534){
                    cout<<endl<<" SynccomfirmOptrancasync error blopnumb>65534"<<endl;
                    exit_call();
                    return;  //error
                }

                bltype = typebl(blksOPSync[i].substr(8, blksOPSync[i].length()-8));
                accstrL= readaccountString(blksOPSync[i].substr(8, blksOPSync[i].length()-8)  , false);
                accstrR= readaccountString(blksOPSync[i].substr(8, blksOPSync[i].length()-8)  , true);
                array <unsigned char,64> acc = accArr(accstrL);
                array <unsigned char, 64> accR = accArr(accstrR);

                std::unique_lock<std::mutex> WritingAccSynclock(WritingAccSync);

                if(mapIndex[accR].indexing==false&&AccSync[accR].indexed==false&&AccSync[accR].indexing==false){
                    AccSync[accR].indexing= true;
                    AccSync[accR].transacSync= false;
                    thread threadslmAccR(searchlastmove ,accstrR, true );
                    threadslmAccR.detach();
                    AccSync[accR].transacNumbrSync = blopnumb;
                }

                if(mapIndex[acc].indexing ==false&&AccSync[acc].indexed== false&&AccSync[acc].indexing==false){
                    AccSync[acc].indexing= true;
                    AccSync[acc].transacSync= false;
                    thread threadslmAccL(searchlastmove ,accstrL, true );
                    threadslmAccL.detach();
                    AccSync[acc].transacNumbrSync = blopnumb;
                }

                if (!AccSync[accR].indexedNumber && !AccSync[accR].transacSync){

                    if(AccSync[accR].transacSync<=blopnumb){
                        AccSync[accR].transacNumbrSync = blopnumb;
                        AccSync[accR].indexedNumber = true;
                    } else {
                        cout<<endl<<" SynccomfirmOptrancasync error AccSync[accR].transacNumbrSync<=blopnumb"<<endl;
                        exit_call();
                        return ; //error
                    }
                }

                if( !AccSync[acc].indexedNumber && !AccSync[acc].transacSync){
                    if(AccSync[acc].transacNumbrSync<=blopnumb){
                        AccSync[acc].transacNumbrSync = blopnumb;
                        AccSync[acc].indexedNumber = true;
                    } else {
                        cout<<endl<<" SynccomfirmOptrancasync error AccSync[acc].transacNumbrSync<=blopnumb"<<endl;
                        exit_call();
                        return ; //error
                    }
                }

                /*
                cout<<endl<<" SynccomfirmOptrancasync debug AccSync[accR].indexed "<<AccSync[accR].indexed<<"  AccSync[acc].indexed "<<AccSync[acc].indexed<<endl;
                cout<<endl<<" AccSync[acc].transacNumbrSync"<<AccSync[acc].transacNumbrSync<<"  AccSync[accR].transacNumbrSync "<<AccSync[accR].transacNumbrSync<<" blopnumb "<<blopnumb;
                cout<<endl<<" AccSync[acc].transacSync "<<AccSync[acc].transacSync<<"  AccSync[accR].transacSync "<<AccSync[accR].transacSync;
                cout<<endl<<" AccSync[acc].NumberCheck "<<AccSync[acc].NumberCheck<<"  AccSync[accR].NumberCheck "<<AccSync[accR].NumberCheck<<endl;
                cout<<" bltype "<<bltype<<endl;
                */
                if ( AccSync[accR].indexed==true && AccSync[acc].indexed ==true 
                    &&   
                        ( (AccSync[acc].transacNumbrSync == blopnumb 
                        && AccSync[acc].transacSync==false && AccSync[acc].NumberCheck == false
                        && AccSync[accR].transacNumbrSync == blopnumb 
                        && AccSync[accR].transacSync==false && AccSync[accR].NumberCheck == false
                        &&(bltype== "02"||bltype== "03"||bltype== "05"||bltype== "07"))

                        ||  

                        ( AccSync[acc].transacNumbrSync == blopnumb 
                        && AccSync[acc].transacSync==true && AccSync[acc].NumberCheck == false
                        && AccSync[accR].transacNumbrSync == blopnumb
                        && AccSync[accR].transacSync==true && AccSync[accR].NumberCheck == false
                        &&(bltype== "00"||bltype== "04"||bltype== "06"||bltype== "08"||bltype == "FF")) 
                        ) 
                ){

                    if(bltype== "02"||bltype== "03"||bltype== "05"||bltype== "07"){
                        if( numberspace[blopnumb] ==false){
                            numberspace[blopnumb]=true;

                        }else {
                            cout<<endl<<" SynccomfirmOptrancasync error numberspace[blopnumb] != false"<<endl;
                            exit_call();
                        }

                    }
                    
                    std::unique_lock<std::mutex> writingspacelock(writingspace);

                    if(bltype == "FF"&&( typebl(blksOP[ blopnumb ]) == "02" || typebl(blksOP[ blopnumb ]) == "03" || typebl(blksOP[ blopnumb ]) == "05"|| typebl(blksOP[ blopnumb ]) == "07" )){
                        accstrL= readaccountString( blksOP[ blopnumb ],false );
                        accstrR= readaccountString( blksOP[ blopnumb ],true );
                        array <unsigned char,64> acc = accArr(accstrL);
                        array <unsigned char,64> accR = accArr(accstrR);
                        blksOP[ blopnumb ] = blksOPSync[i].substr(8, blksOPSync[i].length()-8);
                        checkTransacSync[i] = true;
                        AccSync[acc].transacNumbrSync++;
                        AccSync[accR].transacNumbrSync++;
                        AccSync[acc].transacSync=false;
                        AccSync[accR].transacSync=false;
                        continue;
                    }

                    unsigned long long newbalanceL= hexToULL(readbalanceString(  blksOPSync[i].substr(8, blksOPSync[i].length()-8)  , false)) ;       
                    unsigned long long newbalanceR= hexToULL(readbalanceString(blksOPSync[i].substr(8, blksOPSync[i].length()-8)  , true)) ;   

                    uint32_t Feed =   hexToUint(FeedOfTransac( blksOPSync[i].substr(8, blksOPSync[i].length()-8)  )); 
                    
                    if(bltype== "02"){
                                         
                        if(AccSync[acc].value-(newbalanceL+Feed) != newbalanceR-AccSync[accR].value
                        || newbalanceL+Feed<newbalanceL || newbalanceL+Feed>=AccSync[acc].value || newbalanceR<=AccSync[accR].value
                        || newbalanceL+Feed + (newbalanceR-AccSync[accR].value) !=AccSync[acc].value
                        || newbalanceL+Feed + (newbalanceR-AccSync[accR].value)<newbalanceL
                        || newbalanceL+Feed + (newbalanceR-AccSync[accR].value)<newbalanceR-AccSync[accR].value

                        ){
                            for(int i = 0; i<5; i++){
                                cout<<endl<<"catch comfirmOptrancasync() (AccSync[acc].value-Feed)-newbalanceL  == newbalanceR-AccSync[accR].value 02"<<endl;
                                cout<<"AccSync[acc].value "<<AccSync[acc].value<<" newbalanceL "<<newbalanceL<<" Feed "<<Feed<<endl;
                                cout<<"AccSync[accR].value "<<AccSync[accR].value<<" newbalanceR "<<newbalanceR<<endl;
                                
                            }
                            exit_call();
                        }else{

                            blksOP[ blopnumb ] = blksOPSync[i].substr(8, blksOPSync[i].length()-8);
                            checkTransacSync[i] = true;
                            AccSync[acc].transacNumbrSync = blopnumb;
                            AccSync[acc].transacSync=true;
                            AccSync[accR].transacNumbrSync = blopnumb;
                            AccSync[accR].transacSync=true;   

                        }
                        
                    }

                    if(bltype== "03"){

                        //falta igualdad a 0 verificar 0005

                        if( AccSync[acc].value-Feed<newbalanceL 

                            || AccSync[acc].value<=Feed
                            || AccSync[accR].value+newbalanceR<=AccSync[accR].value
                    
                        ){

                            for(int i = 0; i<5; i++){
                                cout<<endl<<"debug error comfirmOptrancasync() (AccSync[acc].value-Feed)>newbalanceL  == newbalanceR>AccSync[accR].value) 0003";
                                exit_call();
                            }

   
                        } else { 
                            blksOP[ blopnumb ] = blksOPSync[i].substr(8, blksOPSync[i].length()-8);
                            checkTransacSync[i] = true;
                            AccSync[acc].transacNumbrSync = blopnumb;
                            AccSync[acc].transacSync=true;
                            AccSync[accR].transacNumbrSync = blopnumb;
                            AccSync[accR].transacSync=true;

                        }
                    } 

                    if(bltype== "05"){

                        if( (AccSync[acc].value-Feed) -newbalanceL != newbalanceR  
                           || AccSync[acc].value-Feed> AccSync[acc].value|| (AccSync[acc].value-Feed) -newbalanceL>AccSync[acc].value 
                           || AccSync[accR].value >=newbalanceR
                        
                        ){
                            for(int i = 0; i<5; i++){
                                cout<<endl<<"catch comfirmOptrancasync() (AccSync[acc].value-newbalanceL+Feed  == newbalanceR) 0005";
                                exit_call();
                            }
 
                        } else { 
                            blksOP[ blopnumb ] = blksOPSync[i].substr(8, blksOPSync[i].length()-8);
                            checkTransacSync[i] = true;
                            AccSync[acc].transacNumbrSync = blopnumb;
                            AccSync[acc].transacSync=true;
                            AccSync[accR].transacNumbrSync = blopnumb;
                            AccSync[accR].transacSync=true; 
                        }
                    }

                    if(bltype== "07"){

                        if( AccSync[acc].value-(newbalanceL+Feed) != newbalanceR-AccSync[accR].value
                        || newbalanceL+Feed < newbalanceL || newbalanceL+Feed >= AccSync[acc].value|| newbalanceR<AccSync[accR].value ||newbalanceR-AccSync[accR].value>=newbalanceR
                        || newbalanceL+Feed + (newbalanceR-AccSync[accR].value)!=AccSync[acc].value
                        || newbalanceL+Feed + (newbalanceR-AccSync[accR].value) <= newbalanceL
                        || newbalanceL+Feed + (newbalanceR-AccSync[accR].value) <  newbalanceR-AccSync[accR].value
                        
                        ){

                            for(int i = 0; i<5; i++){
                                cout<<endl<<"catch comfirmOptrancasync() (newbalanceL+Feed  == newbalanceR-AccSync[accR].value) 0007";
                                exit_call();
                            }

                        } else { 

                            blksOP[ blopnumb ] = blksOPSync[i].substr(8, blksOPSync[i].length()-8);
                            checkTransacSync[i] = true;
                            AccSync[acc].transacNumbrSync = blopnumb;
                            AccSync[acc].transacSync=true;
                            AccSync[accR].transacNumbrSync = blopnumb;
                            AccSync[accR].transacSync=true;   
                        }
                    }




                    if(bltype== "00"){
                        if ( switchBlType(blksOP[ blopnumb ]) ==  blksOPSync[i].substr(8, blksOPSync[i].length()-8).substr(0, 302)   ){
                            string hidden =idBlckchn+shaLBB()+ SHAstg(matchMinQueue());
                            if(FIRMCheck2( blksOPSync[i].substr(8, blksOPSync[i].length()-8).substr(0, 438) ,  hidden   )) {
                                blksOP[ blopnumb ] = blksOPSync[i].substr(8, blksOPSync[i].length()-8);
                                checkTransacSync[i] = true;
                                AccSync[acc].transacNumbrSync++;
                                AccSync[accR].transacNumbrSync++;
                                AccSync[acc].transacSync=false;
                                AccSync[accR].transacSync=false;
                                AccSync[acc].value=newbalanceL;
                                AccSync[accR].value=newbalanceR;
                                transacsconfirmed++;

                            }else { for(int i = 0; i<5; i++){
                                cout<<endl<<"debug error comfirmOptrancasync() FIRMCheck2 ";
                                exit_call();
                            } }
                        } else { for(int i = 0; i<5; i++){
                            cout<<endl<<"debug error comfirmOptrancasync() switchBlType(blksOP[ hexToInt(blOpNmbr(blksOPSync[i].substr(0,8))) ]) ==  blksOPSync[i].substr(8, blksOPSync[i].length()-8).substr(0, 384) 00";
                            exit_call();
                            }
                        }
                    }

                    if(bltype== "04"){
                        if ( switchBlType(blksOP[ blopnumb ]) ==  blksOPSync[i].substr(8, blksOPSync[i].length()-8).substr(0, 302)   ){
                            string hidden =idBlckchn+shaLBB()+ SHAstg(matchMinQueue());
                            if(FIRMCheck2( blksOPSync[i].substr(8, blksOPSync[i].length()-8).substr(0, 438) ,  hidden   )) {
                                blksOP[ blopnumb ] = blksOPSync[i].substr(8, blksOPSync[i].length()-8);
                                checkTransacSync[i] = true;
                                AccSync[acc].transacNumbrSync++;
                                AccSync[accR].transacNumbrSync++;
                                AccSync[acc].transacSync=false;
                                AccSync[accR].transacSync=false;
                                AccSync[acc].value-=newbalanceL+Feed;
                                AccSync[accR].value+=newbalanceL;
                                transacsconfirmed++;

                            }else { for(int i = 0; i<5; i++){
                            cout<<endl<<"debug error comfirmOptrancasync() FIRMCheck2 ";
                            exit_call();
                            } }
                        } else { for(int i = 0; i<5; i++){
                            cout<<endl<<"debug error comfirmOptrancasync() switchBlType(blksOP[ hexToInt(blOpNmbr(blksOPSync[i].substr(0,8))) ]) ==  blksOPSync[i].substr(8, blksOPSync[i].length()-8).substr(0, 384) 0004";
                            exit_call();
                            }
                        }
                    }

                    if(bltype== "06"){
                        if ( switchBlType(blksOP[ blopnumb ]) ==  blksOPSync[i].substr(8, blksOPSync[i].length()-8).substr(0, 302)    ){
                            string hidden =idBlckchn+shaLBB()+ SHAstg(matchMinQueue());
                            if(FIRMCheck2( blksOPSync[i].substr(8, blksOPSync[i].length()-8).substr(0, 438) ,  hidden   )) {
                                blksOP[ blopnumb ] = blksOPSync[i].substr(8, blksOPSync[i].length()-8);
                                checkTransacSync[i] = true;
                                AccSync[acc].transacNumbrSync++;
                                AccSync[accR].transacNumbrSync++;
                                AccSync[acc].transacSync=false;
                                AccSync[accR].transacSync=false;
                                AccSync[acc].value=newbalanceL;
                                AccSync[accR].value+=newbalanceR;
                                transacsconfirmed++;

                            }else { for(int i = 0; i<5; i++){
                            cout<<endl<<"debug error comfirmOptrancasync() FIRMCheck2 ";
                            exit_call();
                            } }
                        } else { for(int i = 0; i<5; i++){
                            cout<<endl<<"debug error comfirmOptrancasync() switchBlType(blksOP[ hexToInt(blOpNmbr(blksOPSync[i].substr(0,8))) ]) ==  blksOPSync[i].substr(8, blksOPSync[i].length()-8).substr(0, 384) 0006";
                            exit_call();
                            }
                        }
                    }

                    if(bltype== "08"){
                        if ( switchBlType(blksOP[ blopnumb ]) ==  blksOPSync[i].substr(8, blksOPSync[i].length()-8).substr(0, 384)   ){
                            string hidden =idBlckchn+shaLBB()+ SHAstg(matchMinQueue());
                            if(FIRMCheck2( blksOPSync[i].substr(8, blksOPSync[i].length()-8).substr(0, 512) ,  hidden   )) {
                                blksOP[ blopnumb ] = blksOPSync[i].substr(8, blksOPSync[i].length()-8);
                                checkTransacSync[i] = true;
                                AccSync[acc].transacNumbrSync++;
                                AccSync[accR].transacNumbrSync++;
                                AccSync[acc].transacSync=false;
                                AccSync[accR].transacSync=false;
                                AccSync[acc].value-=newbalanceL+Feed;
                                AccSync[accR].value=newbalanceR;
                                transacsconfirmed++;

                            }else { for(int i = 0; i<5; i++){
                            cout<<endl<<"debug error comfirmOptrancasync() FIRMCheck2 ";
                            exit_call();
                            } }
                        } else { for(int i = 0; i<5; i++){
                            cout<<endl<<"debug error comfirmOptrancasync() switchBlType(blksOP[ hexToInt(blOpNmbr(blksOPSync[i].substr(0,8))) ]) ==  blksOPSync[i].substr(8, blksOPSync[i].length()-8).substr(0, 384) 0008";
                            exit_call();
                            }
                        }
                    }

                }
            
                if(!AccSync[accR].transacSync){
                    AccSync[accR].NumberCheck = true;
                }
                if(!AccSync[acc].transacSync){
                    AccSync[acc].NumberCheck = true;
                }

                WritingAccSynclock.unlock();

                if (transacsconfirmed==blksize){
                    break;
                } else {
                    if(transacsconfirmed>blksize){
                        cout<<endl<<"comfirmOptrancasync() error transacsconfirmed>blksize";
                        exit_call();
                    }
                }
            }
        }

        
        blkQueuemtxlock.unlock();

        std::unique_lock<std::mutex> WritingAccSynclock(WritingAccSync);

        if (AccSync.size()>0){
            for (auto const& x : AccSync){
                if(AccSync[x.first].indexedNumber==true){
                    AccSync[x.first].indexedNumber=false;
                }
                if(AccSync[x.first].NumberCheck==true){
                    AccSync[x.first].NumberCheck = false;
                }
            }
        }
        WritingAccSynclock.unlock();
        comfirmOptrancasyncRun = false;

      //  cout<<endl<<"   <==== SynccomfirmOptrancasync end"<<endl;

        std::this_thread::sleep_for(std::chrono::seconds(1));

    }

}

void firewallCountTime(){
    while(true){

    // do something
    
        std::unique_lock<std::mutex> allowIpmtxlock(allowIpmtx);
        AllowIp.clear();
        firewallcheck=false;
        allowIpmtxlock.unlock();

        std::this_thread::sleep_for(std::chrono::seconds(60));
    }
}

void Syncqueue(){

    //cout<<endl<<" Syncqueue init ====>"<<endl;

    if(synced&&!Refactorizing&&matchminRounInit){

        if(!syncqueue&& matchMinQueueIp()!= "localhost"&&!Refactorizing&&synced ){

            syncqueue = true;

            //Request Transaction from last retrieved to last in network
            vector<string> newblkop = blkOpSync(blksOPSync.size(),0,ShaLBBBuffered);

            if(newblkop[0]=="syncedToLastOp"||newblkop[0]=="RefactorizingLastBl"){
                syncqueue=false;
                return;
            }

            if(newblkop[0]=="00"||newblkop[0]=="01"||newblkop[0]=="02"){
                if(newblkop[0]=="02"){
                    matchminRounInit=false;
                }
                syncqueue=false;
                cout<<endl<<"thread Syncqueue newblkop[0]==00||newblkop[0]==01 "<<newblkop[0]<<endl;
                cout<<endl<<" <==== syncqueue alg end"<<endl;
                return;
            }

            for(int i =0;i<newblkop.size();i++){
                cout<<" "<<newblkop[i]<<" ";
            }
        
            int newblkint = 0;

            std::unique_lock<std::mutex> blkQueuemtxlock(blkQueuemtx);

            if(blksOPSync.size()==0){

                if ( hexToInt(newblkop[0].substr(0 , 8)) > maxblksize || newblkop[0].length() != 136 ){
                    cout<<endl<<"Syncqueue() error from node sync hexToInt(newblkop[0].substr(0 , 8)) > maxblksize "<<endl;
                    // skip node queue
                    exit_call();
                    return ;
                }

                blksize = hexToInt(newblkop[0].substr(0 , 8));
                dir_feeds = newblkop[0].substr(8 , 130);
                blksOPSync.push_back(newblkop[newblkint]);
                newblkop.erase(newblkop.begin() + 0);  
                syncOpNumbr++;
                cout<<endl<<"Size of new BL of Pair "<<blksize<<endl;
            }

            int blksyncsize = blksOPSync.size();
            int newblksyncsize = newblkop.size()-1;

			
            for(int i =blksyncsize; i<newblksyncsize+blksyncsize;i++ ){

                blksOPSync.push_back(newblkop[newblkint]);  
                // ver si se peude quitar esto 
                checkTransacSync[blksOPSync.size()-1]= false;
                newblkint++;
                syncOpNumbr++;

            }

            //cout<<endl<<" <==== syncqueue alg end"<<endl;
            syncqueue = false;
        }
    }
cout<<endl<<" <==== syncqueue alg end"<<endl;
}

void timetransacthread(){
    while(true){

        std::unique_lock<std::mutex> writingspacelock(writingspace);

        for(int i = 0; i<maxblksize;i++){
            if (std::time(nullptr)>transactime[i] && transactime[i]!=9999&&typebl(blksOP[i])!="FF"&&typebl(blksOP[i])!="00"&& typebl(blksOP[i])!="04"&& typebl(blksOP[i])!="06"&& typebl(blksOP[i])!="08"){
                uint64_t valuectx = 0;
                if(!changeBlType(blksOP[i], "FF", valuectx)){
                    cout<<endl<<"error timetransacthread() !changeBlType(blksOP[i], FF, valuectx)"<< blksOP[i]<<" "<<valuectx;
                    exit_call();
                }

                std::unique_lock<std::mutex> pricesingtransacCountlock(pricesingtransacCount);
                if(transacpendingcount>0){
                    transacpendingcount--;
                }
                pricesingtransacCountlock.unlock();
                std::unique_lock<std::mutex> blkQueuemtxlock(blkQueuemtx);
                blksOPSyncQueue.push_back(intToHex(i)+blksOP[i].substr(0,302));
                cout<<"transac N "<<i<<" Timeout."<<endl;
            }
            
        }

        writingspacelock.unlock();
        
        // Espera el intervalo de tiempo
        std::this_thread::sleep_for(std::chrono::seconds(1));
            
    }
}

void AliveConnection(){

    while(true){

       // cout<<endl<<"======== > alive init"<<endl;

        std::unique_lock<std::mutex> peerssyncblocklock(peerssyncblock);
        auto Nodes2 = Nodes;
        peerssyncblocklock.unlock();

        auto it = Nodes2.begin();
        while (it != Nodes2.end()) {
    
            if (it->second.ip == "localhost"||it->second.ip== "unavailable" ) {
                ++it;
                continue;
            }

            if(!itsAlive(  it->first ,ShaLBBBuffered)&& it->first != publicDirNode){

                peerssyncblocklock.lock();

                auto iter  = Nodes.find(it->first);
                if (iter != Nodes.end()){
                    Nodes[it->first].ip = "unavailable";
                    Nodes[it->first].logged = false;
                    peerssyncblocklock.unlock();
                }

                cout<<endl<< " Node Logout"<<it->first<<endl;
                
            } else {
               // cout<<endl<<"Its Alive OK"<<endl;
            }

            ++it;

        }

        reAlive(1000);
  
       // cout<<endl<<" alive end <========"<<endl;
        std::this_thread::sleep_for(std::chrono::seconds(4));
    }
    
}

void statusCheck(){

    while(true){
        
        if(matchMinQueueIp()!="localhost"&&!Refactorizing&&matchminRounInit&&synced){
            
            // cout<<endl<<"statusCheck init =====> "<<endl;
            statusCheckRun = true;

            std::unique_lock<std::mutex> queuetransacsmtxlock(queuetransacsmtx);
            map<string, string> queuetransacsIteration (queuetransacs);
            queuetransacsmtxlock.unlock();

            if (!queuetransacsIteration.empty()) {
                auto it = queuetransacsIteration.begin();
                while (it != queuetransacsIteration.end()) {
                    
                    string str = it->first;
                    if(it->second.length() == 64){

                        string response = curlpost2("https://"+ matchMinQueueIp()+"/queuetransacs", it->second, 4000);

                        if(response == "processing"){
                            ++it; 
                            continue;
                        }
                        queuetransacsmtxlock.lock();
                        queuetransacs[str] = response;
                        queuetransacsmtxlock.unlock();
                        
                    }
                    ++it;
                    
                }
            }
            //cout<<endl<<"<=====statusCheck end  "<<endl;
        }
               
        statusCheckRun = false;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

void syncnetwork_matchMinRound(){

    extern uint shamatchinstep;
    uint syncinterval = 0;

    uint8_t retries = 0;
    while(true){

     //   cout<<endl<<"======== > matchMinRound init"<<endl;

        if(syncinterval>15){
            syncNetwork();
            syncinterval= 0;
        }

        syncinterval++;

        if(synced&&!Refactorizing){
            
           // cout<<endl<<"PeersLogged: "<<PeersLogged();
            //cout<<endl<<"peersObj.size(): "<<Nodes.size();
           // cout<<endl<<"matchMinRound (PeersLogged()*10000)/peersObj.size()>51% "<<(PeersLogged()*10000)/Nodes.size()<<endl;
            
            if(  (PeersLogged()*10000)/Nodes.size() >= 5100 &&synced &&!Refactorizing){ 

                if(!matchminRounInit&&!Refactorizing) {

                    ClearOpBlks();

                    //cout<<endl<<" MatchMin building queue "<<endl;
                                                                  
                    //2.1
                    int timingRound2 = stoi(timing())+6;

                    switch ( ShaMinInit()) {
                        case 1:
                            if( matchMinBuildQueueFromNetwork() ) {
                                shamatchinstep = 4;
                                break;
                            }
                            continue;
                        case 0:
                            //2.3
                            if(!sortMatchMin()){
                                cout<<endl<<"MatchMin building queue fail !sortMatchMin()"<<endl;
                                shamatchinstep = 0;
                                clearMatchminProposal();
                                std::this_thread::sleep_for(std::chrono::seconds(1));
                                continue;
                            }
                            timingbl = time(nullptr)+Maxtimingbl;
                            break;
                        case 2: 
                            cout<<endl<<"shamin round init fail case 2"<<endl;
                            std::this_thread::sleep_for(std::chrono::seconds(2));
                            continue;
                            break;
                        default:
                            break;
                    }
                    
                    int timing2 = stoi(timing());

                    if ( timingRound2 > timing2 ){
                        std::this_thread::sleep_for(std::chrono::seconds(timingRound2-timing2));
                    }

                    //cout<<endl<<" MatchMin Pre Round check "<<endl;
                    //3.2
                    if(MatchCheckDW()){

                        matchminRounInit = true;
                        //cout<<endl<<" check ok"<<endl;
                        std::this_thread::sleep_for(std::chrono::seconds(4));

                    } else{ 
                        cout<<endl<<"check fail"<<endl;
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                        continue;
                    }

                    errorMatchminCount = 0;

                }

                if(!postRefactRoundInit&&matchminRounInit&&!Refactorizing){
                    cout<<endl<<"Construction of the new block has started"<<endl;
                    if(lastbllocalmatchsync()&&lastblDWULL==lastblockbuilt()){

                        if(matchMinQueueIp() == "localhost"){

                            blksize = maxblks();
                            dir_feeds = feedToDirset();
                            std::unique_lock<std::mutex> blkQueuemtxlock(blkQueuemtx);
                            blksOPSyncQueue.push_back(intToHex(blksize)+dir_feeds);
                            blkQueuemtxlock.unlock();

                        } else {
                            //cout<<endl<<"debug thread matchminround matchMinQueueIp() != localhost "<<matchMinQueueIp()<<" "<<matchMinQueue()<<endl;
                        }
                        timingbl = time(nullptr)+Maxtimingbl;
                        postRefactRoundInit = true;
                    }
                    //cout<<endl<<"thread matchminround lastbllocalmatchsync()&&lastblDWULL==lastblockbuild() "<<matchMinQueue()<<" "<<lastblDWULL<<" "<<lastblockbuild()<<endl;
                }

                if(!Refactorizing && !Refactoring_internalSecu && matchminRounInit && synced && postRefactRoundInit){

                    if (matchMinQueueIp()!= "localhost"){
                        Syncqueue();
                    }
                    if (transacsconfirmed==blksize || time(nullptr)> timingbl && !Refactorizing && !Refactoring_internalSecu){

                        if( time(nullptr)> timingbl && !Refactorizing && !Refactoring_internalSecu ){

                            cout<<"Enought Timing Block - forced refact"<<endl;

                        } else{
                            cout<<endl<<" transactions confirmed qtty limit reach, refact validate init called from syncnetworkThread "<<endl;
                        }

                        refactvalidate();

                    } else {
                        if(transacsconfirmed>blksize){
                            cout<<endl<<"comfirmOptrancasync() error transacsconfirmed>blksize";
                            exit_call();
                        }
                    }
                }

                if(syncinterval ==3){

                    if(MatchCheckDW() ){
                        //cout<<endl<<" check ok"<<endl;
                    } else{ 

                        cout<<endl<<"MatchMin network check Fail "<<endl;
                        std::unique_lock<std::mutex> peersMatchMinBlockmtxlock(peersMatchMinBlockmtx);
                        peersMatchMin.clear();
                        peersMatchMinBlockmtxlock.unlock();

                        std::unique_lock<std::mutex> blkQueuemtxlock(blkQueuemtx);

                        matchminRounInit=false;
                        postRefactRoundInit = false;
                        size_t blksOPSyncQueuesize= blksOPSyncQueue.size();
                        if(BlAntIsMatch){
                            for(int i = lastmatchsyncqueue; i<blksOPSyncQueuesize; i++ ){
                                blksOPSyncQueue.pop_back();
                            }
                        } else {
                            blksOPSyncQueue.clear();
                        }
                        
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                        continue;
                    }
                }
            }
        }
        // "<< matchminRounInit<<endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

#endif

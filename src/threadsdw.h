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
extern int32_t transacscomfirmed;
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

void getdatatransacthread1 (string queuetransac, string FromDir, string ToDir,  string value, string firm){

    std::unique_lock<std::mutex> queuetransacsmtxlock(queuetransacsmtx);

    if ( matchMinQueueIp() == "localhost"){

        string stg1 = DataTransac(FromDir, ToDir, hexToULL(value),feeds_ratio);
        cout<<endl<<" debug getdatatransacthread1 DataTransac "<<stg1;
        
        if (stg1.length() != 494) {
            cout<<endl<<"DataTransac error !length : "<<stg1.length()<<"   "<<stg1<<endl;
            queuetransacs[queuetransac] = "DataTransac error !length : "+ stg1;
            return;
        }

        std::unique_lock<std::mutex> writingspacelock(writingspace);
        
        vector<unsigned char> vec;
        addHexStringInVector(vec, stg1);
        uint blkSpace = WriteSpaceOp (vec);
        blksOP[blkSpace] = stg1;

        // alg 1.0
        // - la peticion debe ser sincronica
        // - verificar espacio disponible de transaccion;
        // - verificar que las direcciones no esten en transacciones pendientes

        string accL = readaccountString(stg1, false);
        string accR = readaccountString(stg1, true);
        uint64_t rests;
        uint8_t PreTransacType =255;

        uint8_t OpTransacType;
        string accBlL;
        string accBlR;
        uint64_t balanceL;
        uint64_t balanceR;

        rests =  hexToULL(readbalanceString(stg1 , false ));

        // primer bucle encuentra si las cuentas estan en una transaccion pendiente y define las restas
        for(int i = 0; i< blkSpace ;i++){

            if( typebl(blksOP[i]) == "FF"){ continue;}

            OpTransacType = typebl2(blksOP[i]);
            if( OpTransacType == 0xFF ){ continue;}
            accBlL = readaccountString(blksOP[i] , false );
            accBlR = readaccountString(blksOP[i] , true );
            balanceL = readbalanceuint64(blksOP[i] , false);
            balanceR = readbalanceuint64(blksOP[i] , true);
            uint feeds = hexToUint(FeedOfTransac(blksOP[i]));


            if ( (accL == accBlL||accR == accBlR||accR == accBlL||accL == accBlR) && (OpTransacType == 2||OpTransacType == 3||OpTransacType == 5||OpTransacType == 7) && blksOP[i] != stg1 ){
                //pre defining 03
                if (accL == accBlL && accR == accBlR || accL == accBlR && accR == accBlL){

                    PreTransacType = 3;

                    if(OpTransacType  == 2   ){
                        cout<<endl<<"OpTransacType  == 2 "<< balanceL<<" "<<balanceR;
                        if(accL == accBlL){
                            rests =  balanceL;
                        } else {
                            rests =  balanceR;
                        }
                    }

                    if(OpTransacType  == 3 ){

                        if(accL == accBlL){
                        
                            if(  rests - (balanceL+feeds)  >=rests || balanceL+feeds < balanceL ){ 
                                cout<<endl<<"bad sums acc transacs";
                                blksOP[blkSpace]= F256+F256;    
                                cout<<endl<<"debug rests "<<rests<< " balanceL "<<balanceL<<endl;
                                queuetransacs[queuetransac] = "bad sums";
                                return;    
                            }

                            rests-=balanceL+feeds; // colocar solo si es accl
                        } 

                    }

                    if(OpTransacType == 5  ){

                        if(accL == accBlL){
                            rests =  balanceL;
                        } 
                    }

                    if(OpTransacType  == 7   ){
                        if(accL == accBlL){
                            if(  rests - (balanceL+feeds)  >=rests || balanceL+feeds < balanceL ){ cout<<endl<<"bad sums acc transacs";
                                blksOP[blkSpace]= F256;    
                                cout<<endl<<"debug rests "<<rests<< " balanceL "<<balanceL<<endl;
                                queuetransacs[queuetransac] = "bad sums";
                                return;    
                            }
                            rests-=balanceL+feeds; // anadir feed

                        } else {
                            rests =  balanceR;
                        }                                                                                                                                                                                       

                    }

                    cout<<endl<<"now PreTransacType is "<<byteToHex2(PreTransacType)<<endl;
                }
                //pre defining 05
                if (PreTransacType != 3&&(accL != accBlL||accL != accBlR)&& (accR == accBlL||accR == accBlR)){
                    PreTransacType = 5;
                    cout<<endl<<"PreTransacType is now "<<PreTransacType<<endl;
                }    
                //pre defining 07
                if (PreTransacType != 3&&(accL == accBlL||accL ==accBlR)&& (accR != accBlL||accR != accBlR)){

                    if(OpTransacType  == 2 ){
                        if(accL == accBlL){
                            rests =  balanceL;
                        } else {
                            rests =  balanceR;
                        }
                    }

                    if(OpTransacType  == 3 ){

                        if(accL == accBlL){
                        
                            if(  rests - (balanceL+feeds)  >=rests || balanceL+feeds < balanceL ){ 
                                cout<<endl<<"bad sums acc transacs";
                                blksOP[blkSpace]= F256+F256;    
                                cout<<endl<<"debug rests "<<rests<< " balanceL "<<balanceL<<endl;
                                queuetransacs[queuetransac] = "bad sums";
                                return;    
                            }

                            rests-=balanceL+feeds; // colocar solo si es accl
                        } 
                    }

                    if(OpTransacType  == 5  ){
                        if(accL == accBlL){
                            rests =  balanceL;
                        } 
                    }

                    if(OpTransacType  == 7 ){
                        if(accL == accBlL){
                            if(  rests - (balanceL+feeds)  >=rests || balanceL+feeds < balanceL ){ 
                                cout<<endl<<"bad sums acc transacs";
                                blksOP[blkSpace]= F256+F256;    
                                cout<<endl<<"debug rests "<<rests<< " balanceL "<<balanceL<<endl;
                                queuetransacs[queuetransac] = "bad sums";
                                return;    
                            }

                            rests-=balanceL+feeds; // colocar solo si es accl
                        } else {

                            rests =  balanceR;
                        }

                    }

                    PreTransacType = 7;
                    cout<<endl<<"PreTransacType is now "<<PreTransacType<<endl;
                }
                //throuht error
                if(PreTransacType != 3&&PreTransacType != 5&&PreTransacType != 7){
                    cout<<endl<<"internal trouble in type of transac OpTransacType not match  - bl @ "<<i <<" : "<< blksOP[i]<<endl;

                    blksOP[blkSpace]= F256+F256;      

                    queuetransacs[queuetransac] = "internal server trouble PreTransacType != bltype";
                    return;   
            
                }
                
                i++;
                
                //segundo bucle comprobacion de cuentas 
                for(i; i<blkSpace ;i++){

                    OpTransacType = typebl2(blksOP[i]);

                    if( OpTransacType == 0xFF ){ 
                        continue;
                    }

                    accBlL = readaccountString(blksOP[i] , false );
                    accBlR = readaccountString(blksOP[i] , true );
                    balanceL = readbalanceuint64(blksOP[i] , false);
                    balanceR = readbalanceuint64(blksOP[i] , true);

                    if ((accL== accBlL || accL == accBlR)&& PreTransacType == 5 && (OpTransacType == 2||OpTransacType == 3||OpTransacType == 5||OpTransacType == 7)){
                        PreTransacType = 3;
                    }

                    if ((accR== accBlL|| accR == accBlR)&& PreTransacType == 7 && (OpTransacType == 2||OpTransacType == 3||OpTransacType == 5||OpTransacType == 7)){
                        PreTransacType = 3;
                    }

                    if((OpTransacType != 3&& OpTransacType != 4 && OpTransacType != 5 && OpTransacType != 6 && OpTransacType != 7 && OpTransacType != 8)
                        || (PreTransacType== 0|| PreTransacType== 2|| PreTransacType== 5||PreTransacType== 6) && accL== accBlL  ){

                        cout<<endl<<"internal server trouble - bl @"<<i <<" : "<< blksOP[i]<<endl;
                        cout<<endl<<"debug blkSpace "<<blkSpace<<" OpTransacType "<<uintToHex(OpTransacType) <<" PreTransacType "<< uintToHex(PreTransacType)<<endl;
                        blksOP[blkSpace]= F256+F256;      
                        queuetransacs[queuetransac] = "internal server trouble OpTransacType != bltype";
                        //cerrar programa error de memoria
                        return;    

                    }

                    if ( accL == accBlL && (OpTransacType == 3||OpTransacType == 4||OpTransacType == 7||OpTransacType == 8) ){

                        // cout<<endl<<" debug rests cond 1  bl= "<<i<<" rests= " <<rests;

                            if(  rests - (balanceL+feeds)  >=rests || balanceL+feeds < balanceL ){ 
                                cout<<endl<<"bad sums acc transacs";
                                blksOP[blkSpace]= F256+F256;    
                                cout<<endl<<"debug rests "<<rests<< " balanceL "<<balanceL<<endl;
                                queuetransacs[queuetransac] = "bad sums";
                                return;    
                            }

                            rests-=balanceL+feeds; // colocar solo si es accl

                    }

                    if ( (accL == accBlR)&&(OpTransacType == 4||OpTransacType == 6) ){
                        if( rests + balanceR <= rests ){ 
                            cout<<endl<<"bad sums acc transacs";
                            blksOP[blkSpace]= F256+F256;    
                            cout<<endl<<"debug rests "<<rests<< " balanceL "<<balanceL<<endl;
                            queuetransacs[queuetransac] = "bad sums";
                            return;    
                        }
                        rests += balanceR;
                    }  

                }
                cout <<endl<<"debug rests "<< rests<<endl;
            }             
                   
        }

        if( PreTransacType == 3 ||PreTransacType == 7 ){
            if(rests <hexToULL(value)+ hexToUint(FeedOfTransac(stg1)) || hexToULL(value)+ hexToUint(FeedOfTransac(stg1)) < hexToULL(value)){
                cout<<endl<<"sums error rests <1 && (PreTransacType == 03 ||PreTransacType == 07) - rests "<<rests<<endl;
                blksOP[blkSpace]= F256+F256;    
                queuetransacs[queuetransac] = "bad sums";
                return;
            }
        }
     
        
        if(blksOP[blkSpace] == stg1 ){

            cout<<endl<<" thread transac number  : "<<hexToInt(blOpNmbr(stg1))-1<<endl;

            changeBlNmbr(stg1, uintToHex(blkSpace+1).substr(4,4));
            cout<<" thread transac number 2 : "<<hexToInt(blOpNmbr(stg1))-1<<endl;

            if(PreTransacType == 3||PreTransacType == 5||PreTransacType == 7){
                cout<<endl<<"PreTransacType pre "<<PreTransacType<<endl;
                //cout<<endl<<"debug stg pre change "<< stg1<<" length "<<stg1.length()<<endl;
                if(!changeBlType(stg1,uintToHex(PreTransacType).substr(6,2), value)){
                    cout<<endl<<"error getdatatransacthread1() !changeBlType(stg1,uintToHex(PreTransacType).substr(6,2), value)"<<endl;
                    exit_call();
                }
                //cout<<endl<<"debug stg post change "<< stg1<<" length "<<stg1.length()<<endl;
                cout<<endl<<"PreTransacType post"<< typebl(stg1) <<endl;
            }

            cout<<" thread transac number 3 : "<<hexToInt(blOpNmbr(stg1))-1<<endl;

            cout<<endl<<" debugging getdatatransac post loop async operation - stg1 "<<stg1<<endl;

            for (auto &c:stg1){c=toupper(c);}

            blksOP[blkSpace] = stg1;

            std::unique_lock<std::mutex> blkQueuemtxlock(blkQueuemtx);
            blksOPSyncQueue.push_back( uintToHex(blkSpace)+stg1.substr(0, 302));
            blkQueuemtxlock.unlock();
                                         
            if(typebl(stg1) == "02"){
                stg1 = switchBlType(stg1);
            }
            if(typebl(stg1) == "03"){
                stg1 = switchBlType(stg1);
            }  
            if(typebl(stg1) == "05"){
                stg1 = switchBlType(stg1);
            }
            if(typebl(stg1) == "07"){
                stg1 = switchBlType(stg1);
            }           
                                                          
            queuetransacs[queuetransac] =  stg1;
            //cout<<endl<<"data transac i space "<<blkSpace<<endl;
            //cout<<endl<<"data transac res body "<<res.body<<endl;
            transactime[blkSpace] = time(nullptr)+transacmaxtime;

            //verificar que la data sea correcta

            cout<<endl<<"   <===   GetDataTransac end thread 0"<<endl;

            //sumar transacpendingcount
            std::unique_lock<std::mutex> pricesingtransacCountlock(pricesingtransacCount);
            transacpendingcount++;
            return;                                                 
        }

        blksOP[blkSpace]= F256+F256;


        cout<<endl<<"error no se encontro el espacio de la transaccion en la memoria"<<endl<<blksOP[blkSpace];
        queuetransacs[queuetransac] = "handle error writing memory";
        return;
    }

    string stg1= shaLBB()+FromDir+ToDir+value+firm;

    string firmm = LocalSigner( stg1);

    string PairDir = "https://" + matchMinQueueIp() + "/block";
    cout<<endl<<"calling "+PairDir +" matchmin: pair " <<endl;
    string jsonval = "{\"x1\": \"" + stg1 + "\", \"x2\": \"" + firmm + "\"}"; 

    string response = curlpost2(PairDir, jsonval, 1000);

    cout<<endl<<"debug response from matchmin block     "  <<response<<endl;

        if(response == "00"){
            cout<<endl<<" response error"<<endl;
            queuetransacs[queuetransac] = " response error from matchmin";
            return;
        }
    
        // meter match max avg de red
        cout << endl<< "response from "+PairDir <<" : " << response << endl;

        if (response.length() == 64){

            queuetransacs[queuetransac] = response;

            cout<<endl<<" debug getdatatransac thr !localhost queuetransacs[queuetransac] definition "<<queuetransacs[queuetransac]<<endl;

            return;
 
        }

    queuetransacs[queuetransac] =  " MatchSHAMin response: fail: " + response;
    return;
        
}

void getdatatransacthread (string queuetransac, string FromDir, string ToDir,  string value, string firm){
    cout<<endl<<"getdatatransacthread init ===========>"<<endl;
    getdatatransacthread1 (queuetransac, FromDir,ToDir, value, firm);
    cout<<endl<<"<============  getdatatransacthread end"<<endl;
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
        if(Refactorizing||!matchminRounInit||!synced){
            std::this_thread::sleep_for(std::chrono::seconds(3));
            continue;
        }

        comfirmOptrancasyncRun = true;

        std::unique_lock<std::mutex> blkQueuemtxlock(blkQueuemtx);

        for(int i = 1; i<=checkTransacSync.size(); i++){

            if(checkTransacSync[i] == false ){

                cout<<endl<<" SynccomfirmOptrancasync debug blksOPSync "<<i<<" "<<blksOPSync[i]<<endl;

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

                cout<<endl<<" SynccomfirmOptrancasync debug AccSync[accR].indexed "<<AccSync[accR].indexed<<"  AccSync[acc].indexed "<<AccSync[acc].indexed<<endl;
                cout<<endl<<" AccSync[acc].transacNumbrSync"<<AccSync[acc].transacNumbrSync<<"  AccSync[accR].transacNumbrSync "<<AccSync[accR].transacNumbrSync<<" blopnumb "<<blopnumb;
                cout<<endl<<" AccSync[acc].transacSync "<<AccSync[acc].transacSync<<"  AccSync[accR].transacSync "<<AccSync[accR].transacSync;
                cout<<endl<<" AccSync[acc].NumberCheck "<<AccSync[acc].NumberCheck<<"  AccSync[accR].NumberCheck "<<AccSync[accR].NumberCheck<<endl;
                cout<<" bltype "<<bltype<<endl;

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

                    cout<<endl<<"debug comfirmOptransac fl2"<<endl;

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

                    cout<<endl<<" SynccomfirmOptrancasync debug flag "<<endl;

                    unsigned long long newbalanceL= hexToULL(readbalanceString(  blksOPSync[i].substr(8, blksOPSync[i].length()-8)  , false)) ;       
                    unsigned long long newbalanceR= hexToULL(readbalanceString(blksOPSync[i].substr(8, blksOPSync[i].length()-8)  , true)) ;   

                    uint32_t Feed =   hexToInt(FeedOfTransac( blksOPSync[i].substr(8, blksOPSync[i].length()-8)  )); 
                    
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
                            cout<<endl<<"debug blksOP[ blopnumb ].size "<<blksOP[ blopnumb ].size()<<endl;
                            cout<<endl<<"debug opsync blksOP[ blopnumb ] definition "<<blksOP[ blopnumb]+idBlckchn+shaLBB()+SHAstg(matchMinQueue())<<endl;
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
                            cout<<endl<<"debug opsync blksOP[ blopnumb ] definition "<<blksOP[ blopnumb]+idBlckchn+shaLBB()+SHAstg(matchMinQueue())<<endl;
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
                            cout<<endl<<"debug opsync blksOP[ blopnumb ] definition "<<blksOP[ blopnumb]+idBlckchn+shaLBB()+SHAstg(matchMinQueue())<<endl;
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
                            cout<<endl<<"debug opsync blksOP[ blopnumb ] definition "<<blksOP[ blopnumb]+idBlckchn+shaLBB()+SHAstg(matchMinQueue())<<endl;
                            checkTransacSync[i] = true;
                            AccSync[acc].transacNumbrSync = blopnumb;
                            AccSync[acc].transacSync=true;
                            AccSync[accR].transacNumbrSync = blopnumb;
                            AccSync[accR].transacSync=true;   
                        }
                    }




                    if(bltype== "00"){
                        cout<<endl<<"debug  comfirmOptrancasync()  fl 00 ";
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
                                transacscomfirmed++;

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
                        cout<<endl<<"debug  comfirmOptrancasync()  fl 4 ";
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
                                transacscomfirmed++;

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
                        cout<<endl<<"debug  comfirmOptrancasync()  fl6 ";
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
                                transacscomfirmed++;

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
                        cout<<endl<<"debug  comfirmOptrancasync()  fl4 ";
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
                                transacscomfirmed++;

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

                if (transacscomfirmed==blksize){
                    break;
                } else {
                    if(transacscomfirmed>blksize){
                        cout<<endl<<"comfirmOptrancasync() error transacscomfirmed>blksize";
                        exit_call();
                    }
                }
            }
        }

        
        blkQueuemtxlock.unlock();

        if (transacscomfirmed==blksize){

            comfirmOptrancasyncRun = false;
            refactvalidate();

        } else {
            if(transacscomfirmed>blksize){
                cout<<endl<<"comfirmOptrancasync() error transacscomfirmed>blksize";
                exit_call();
            }
        }

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
                cout<<endl<<"debug opsync bucle newblksyncsize+blksyncsize  "<<newblksyncsize+blksyncsize<<endl;
                // blksOP[ hexToInt(blksOPSync[syncOpNumbr].substr(0,8)) ] = blksOPSync[syncOpNumbr].substr(8,blksOPSync[syncOpNumbr].length()-8);
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
                string valuectx =  ullToHex(0);
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

                cout<<endl<< "Logout Node "<<it->first<<endl;
                
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
                        cout<<endl<<"statusCheck debug response from matchmin: " << response<<endl ;

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

                    cout<<endl<<" MatchMin building queue "<<endl;
                                                                  
                    //2.1
                    int timingRound2 = stoi(timing())+6;

                    switch ( ShaMinInit()) {
                        case 1:
                            if( matchMinBuildQueueFromNetwork() ) {
                                shamatchinstep = 4;
                                break;
                                timingbl; //  this is update by matchMinBuildQueueFromNetwork()
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

                    cout<<endl<<" MatchMin Pre Round check "<<endl;
                    //3.2
                    if(MatchCheckDW()){

                        matchminRounInit = true;
                        cout<<endl<<" check ok"<<endl;
                        std::this_thread::sleep_for(std::chrono::seconds(4));

                    } else{ 
                        cout<<endl<<"check fail"<<endl;
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                        continue;
                    }

                    errorMatchminCount = 0;

                }

/*
                //anadir 3 retrys
                if(ShaMinInit()!=1){
                    retries++;
                    if(retries>2){
                        cout<<endl<<"MatchMin network check Fail - OK"<<endl;

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
                        
                        continue;
                    }else{
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                        continue;
                    }
                } else {
                    retries=0;
                    cout<<endl<<"MatchMin network check Running - OK"<<endl;
                }
*/

                if(!postRefactRoundInit&&matchminRounInit&&!Refactorizing){
                    cout<<endl<<"Start to build New Block"<<endl;
                    if(lastbllocalmatchsync()&&lastblDWULL==lastblockbuild()){

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

                if(!Refactorizing&&matchminRounInit&&synced&&postRefactRoundInit){
                    if (matchMinQueueIp()!= "localhost"){
                        Syncqueue();
                    }
                    if(time(nullptr)>timingbl){
                        cout<<"Enought Timing Block - forced refact"<<endl;
                        refactvalidate();
                    }

                    /*
                    if(matchMinQueueIp() == "localhost"){

                        if(MatchCheckDW()){
                            cout<<endl<<" check ok"<<endl;
                        } else{ 

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
                            cout<<endl<<"check fail"<<endl;
                            std::this_thread::sleep_for(std::chrono::seconds(1));
                            continue;
                        }   
                        
                    }
                    */
                }

                if(syncinterval ==3){

                    if(MatchCheckDW() ){
                        cout<<endl<<" check ok"<<endl;
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

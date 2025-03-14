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

#ifndef TRANSACTIONTYPE_H
#define TRANSACTIONTYPE_H

#include <iostream>

struct TransactionElements{

    bool IsConfirmed;
    bool haveAccR;
    bool ValLIsDef;
    bool ValRIsDef;

    uint8_t POS_addressL_Bytes;
    uint8_t POS_valueL_Bytes;
    uint8_t POS_addressR_Bytes;
    uint8_t POS_valueR_Bytes;
    uint8_t POS_metadaPostAcc_Bytes;
    uint8_t POS_transactionValue_Bytes;
    uint8_t POS_transactionNumber_Bytes;
    uint8_t POS_feed_Bytes;
    uint8_t POS_Msg32bytes_Bytes;
    uint8_t POS_signature_Bytes;
    uint8_t POS_hidden_Bytes;
    uint8_t POS_signatureWithHidden_Bytes;

    // position string

    uint8_t POS_addressL_string;
    uint8_t POS_valueL_string;
    uint8_t POS_addressR_string;
    uint16_t POS_valueR_string;
    uint8_t POS_transactionValue_string;
    uint16_t POS_transactionNumber_string;
    uint16_t POS_feed_string;
    uint8_t POS_Msg32bytes_string;
    uint16_t POS_signature_string;
    uint16_t POS_hidden_string;
    uint16_t POS_signatureWithHidden_string;

    //length of bytes elements

    uint8_t size_address_Bytes;
    uint8_t size_value_Bytes;
    uint8_t size_transactionNumber_Bytes;
    uint8_t size_feed_Bytes;
    uint8_t size_Msg32bytes_Bytes;
    uint8_t size_signature_Bytes;
    uint8_t size_hidden_Bytes;
    uint8_t size_TransactionWithsignWoHidden_Bytes;
    uint8_t size_TransactionOnlyData_Bytes;
    uint16_t size_fullTransaction_Bytes;

    //length of string elements

    uint8_t size_address_string;
    uint8_t size_value_string;
    uint8_t size_transactionNumber_string;
    uint8_t size_feed_string;
    uint8_t size_Msg32bytes_string;
    uint8_t size_signature_string;
    uint8_t size_hidden_string;
    uint16_t size_TransactionWithsignWoHidden_string;
    uint16_t size_fullTransaction_String;

};

struct TransactionDBElements{ 

    uint8_t CompressTypeTransaction;
    uint8_t TypeTransaction;
    uint8_t size;
    uint8_t accLPos;
    bool AccLIsCompressed;
    bool HaveAccR;
    uint8_t accRPos;
    bool AccRIsCompressed;
    bool HaveValR;
    bool ValLIsCompressed;
    bool ValRIsCompressed;
    uint8_t valueLPos;
    uint8_t valueRPos;
    uint8_t metadaPostAccPos;
    uint8_t metadaPostAccEndPos;

};

unordered_map<uint8_t, TransactionDBElements> DbTransaction = {

    {0x00, {0x00, 0x00, 215, 1, false, true, 73, false, true, false, false, 65,137, 145, 151}},
    {0x04, {0x04, 0x04, 207, 1, false, true, 73, false, true, false, false, 65,137, 137, 143}},
    {0x06, {0x06, 0x06, 215, 1, false, true, 73, false, true, false, false, 65,137, 145, 151}},
    {0x08, {0x08, 0x08, 215, 1, false, true, 73, false, true, false, false, 65,137, 145, 151}},

    {0x0B,{0x0B, 0x00, 155, 1, true, true, 13, false, true, false, false, 5, 77, 85, 91 }},
    {0x0C,{0x0C, 0x00, 155, 1, false, true, 73, true, true, false, false, 65, 77, 85, 91 }},
    {0x0D,{0x0D, 0x00, 211, 1, false, true, 69, false, true, true, false, 65, 133, 141, 147 }},
    {0x0E,{0x0E, 0x00, 211, 1, false, true, 73, false, true, false, true, 65, 137, 141, 147}},
    {0x0F,{0x0F, 0x00, 207, 1, false, true, 69, false, true, true, true, 65, 133, 137, 143}},
    {0x10,{0x10, 0x00, 151, 1, true, true, 9, false, true, true, false, 5, 73, 81, 87}},
    {0x11,{0x11, 0x00, 151, 1, true, true, 13, false, true, false, true, 5, 77, 81, 87}},
    {0x12,{0x12, 0x00, 147, 1, true, true, 9, false, true, true, true, 5, 73,  77, 83}},
    {0x13,{0x13, 0x00, 151, 1, false, true, 69, true, true, true, false, 65, 73, 81, 87}},
    {0x14,{0x14, 0x00, 151, 1, false, true, 73, true, true, false, true, 65, 77, 81, 87}},
    {0x15,{0x15, 0x00, 147, 1, false, true, 69, true, true, true, true, 65, 73, 77, 83 }},
    {0x16,{0x16, 0x00, 95, 1, true, true, 13, true, true, false, false, 5, 17, 25, 31}},
    {0x17,{0x17, 0x00, 91, 1, true, true, 9, true, true, true, false, 5, 13,  21, 27}},
    {0x18,{0x18, 0x00, 91, 1, true, true, 13, true, true, false, true, 5, 17, 21, 27}},
    {0x19,{0x19, 0x00, 87, 1, true, true, 9, true, true, true, true, 5, 13, 17, 23 }},

    {0x1A,{0x1A, 0x04, 147, 1, true, true, 13, false, true, false, false, 5, 5, 77, 83}},
    {0x1B,{0x1B, 0x04, 147, 1, false, true, 73, true, true, false, false, 65, 65, 77, 83}},
    {0x1C,{0x1C, 0x04, 203, 1, false, true, 69, false, true, true, true, 65, 65, 133, 139}},
    {0x1F,{0x1F, 0x04, 143, 1, true, true, 9, false, true, true, true, 5, 5, 73, 79}},
    {0x22,{0x22, 0x04, 143, 1, false, true, 69, true, true, true, true, 65, 65, 73, 79}},
    {0x25,{0x25, 0x04, 87, 1, true, true, 13, true, true, false, false, 5, 5, 17, 23}},
    {0x26,{0x26, 0x04, 83, 1, true, true, 9, true, true, true, true, 5, 5, 13, 19}},

    {0x29,{0x0B, 0x06, 155, 1, true, true}},
    {0x2A,{0x0C, 0x06, 155, 1, false, true}},
    {0x2B,{0x0D, 0x06, 211, 1, false, true}},
    {0x2C,{0x0E, 0x06, 211, 1, false, true}},
    {0x2D,{0x0F, 0x06, 207, 1, false, true}},
    {0x2E,{0x10, 0x06, 151, 1, true, true}},
    {0x2F,{0x11, 0x06, 151, 1, true, true}},
    {0x30,{0x12, 0x06, 147, 1, true, true}},
    {0x31,{0x13, 0x06, 151, 1, false, true}},
    {0x32,{0x14, 0x06, 151, 1, false, true}},
    {0x33,{0x15, 0x06, 147, 1, false, true}},
    {0x34,{0x16, 0x06, 95, 1, true, true}},
    {0x35,{0x17, 0x06, 91, 1, true, true}},
    {0x36,{0x18, 0x06, 91, 1, true, true}},
    {0x37,{0x19, 0x06, 87, 1, true, true}},

    {0x38,{0x0B, 0x08, 155, 1, true, true}},
    {0x39,{0x0C, 0x08, 155, 1, false, true}},
    {0x3A,{0x0D, 0x08, 211, 1, false, true}},
    {0x3B,{0x0E, 0x08, 211, 1, false, true}},
    {0x3C,{0x0F, 0x08, 207, 1, false, true}},
    {0x3D,{0x10, 0x08, 151, 1, true, true}},
    {0x3E,{0x11, 0x08, 151, 1, true, true}},
    {0x3F,{0x12, 0x08, 147, 1, true, true}},
    {0x40,{0x13, 0x08, 151, 1, false, true}},
    {0x41,{0x14, 0x08, 151, 1, false, true}},
    {0x42,{0x15, 0x08, 147, 1, false, true}},
    {0x43,{0x16, 0x08, 95, 1, true, true}},
    {0x44,{0x17, 0x08, 91, 1, true, true}},
    {0x45,{0x18, 0x08, 91, 1, true, true}},
    {0x46,{0x19, 0x08, 87, 1, true, true}},

    {0x1D,{0x1D, 0x0A, 179, 3, false, false, 0, false, true, false, false, 67, 75, 83, 115}},
    {0x1E,{0x1E, 0x0A, 175, 3, false, false, 0, false, true, false, true, 67, 75, 79, 111}},
    {0x20,{0x20, 0x0A, 175, 3, false, false, 0, false, true, true, false, 67, 71, 79, 111}},
    {0x21,{0x21, 0x0A, 171, 3, false, false, 0, false, true, true, true, 67, 71, 75, 107}},
    {0x23,{0x23, 0x0A, 119, 3, true, false, 0, false, true, false, false, 7, 15, 23, 55}},
    {0x24,{0x24, 0x0A, 115, 3, true, false, 0, false, true, false, true, 7, 15, 19, 51}},
    {0x27,{0x27, 0x0A, 115, 3, true, false, 0, false, true, true, false, 7,11, 19, 51}},
    {0x28,{0x28, 0x0A, 111, 3, true, false, 0, false, true, true, true, 7, 11, 15, 47}},

    {0x47,{0x47, 0x0C, 171, 3, false, false, 0, false, false, false, false, 67, 0, 75, 107}},
    {0x48,{0x48, 0x0C, 167, 3, false, false, 0, false, false, true, false, 67, 0, 71, 103}},
    {0x49,{0x49, 0x0C, 111, 3, true, false, 0, false, false, false, false, 7, 0, 15, 47}},
    {0x4A,{0x4A, 0x0C, 107, 3, true, false, 0, false, false, true, false, 7, 0, 11, 43}},

};

unordered_map<uint8_t, uint8_t> CompressionBytesSizeInstance(){

    std::unordered_map<uint8_t, uint8_t> TransactionSizeCompression = {

        {0x00, 215},
        {0x04, 207},
        {0x06, 215},        
        {0x08, 215},

        {0x0B, 155},
        {0x0C, 155},
        {0x0D, 211},
        {0x0E, 211},
        {0x0F, 207},
        {0x10, 151},
        {0x11, 151},
        {0x12, 147},
        {0x13, 151},
        {0x14, 151},
        {0x15, 147},
        {0x16, 95},
        {0x17, 91},
        {0x18, 91},
        {0x19, 87},

        {0x1A, 147},
        {0x1B, 147},
        {0x1C, 203},
        {0x1F, 143},
        {0x22, 143},
        {0x25, 87},
        {0x26, 83},

        {0x29, 155},
        {0x2A, 155},
        {0x2B, 211},
        {0x2C, 211},
        {0x2D, 207},
        {0x2E, 151},
        {0x2F, 151},
        {0x30, 147},
        {0x31, 151},
        {0x32, 151},
        {0x33, 147},
        {0x34, 95},
        {0x35, 91},
        {0x36, 91},
        {0x37, 87},

        {0x38, 155},
        {0x39, 155},
        {0x3A, 211},
        {0x3B, 211},
        {0x3C, 207},
        {0x3D, 151},
        {0x3E, 151},
        {0x3F, 147},
        {0x40, 151},
        {0x41, 151},
        {0x42, 147},
        {0x43, 95},
        {0x44, 91},
        {0x45, 91},
        {0x46, 87 },

        {0x1D, 179},
        {0x1E, 175},
        {0x20, 175},
        {0x21, 171},
        {0x23, 119},
        {0x24, 115},
        {0x27, 115},
        {0x28, 111},

        {0x47, 171},
        {0x48, 167},
        {0x49, 111},
        {0x4A, 107}

    };

    return TransactionSizeCompression;

}

void DataTransacFormatTypeInstance0x00(std::unordered_map<uint8_t, TransactionElements>& TransactionDataFormat, uint8_t key){

        TransactionDataFormat[key].haveAccR = true;

        TransactionDataFormat[key].POS_addressL_Bytes = 1;
        TransactionDataFormat[key].POS_valueL_Bytes = 65;
        TransactionDataFormat[key].POS_addressR_Bytes = 73;
        TransactionDataFormat[key].POS_valueR_Bytes=137;
        TransactionDataFormat[key].POS_metadaPostAcc_Bytes=145;
        TransactionDataFormat[key].POS_transactionNumber_Bytes=145;
        TransactionDataFormat[key].POS_feed_Bytes=147;
        TransactionDataFormat[key].POS_signature_Bytes=151;
        TransactionDataFormat[key].POS_hidden_Bytes=151;
        TransactionDataFormat[key].POS_signatureWithHidden_Bytes=247;

    // position string

        TransactionDataFormat[key].POS_addressL_string = 2;
        TransactionDataFormat[key].POS_valueL_string = 130;
        TransactionDataFormat[key].POS_addressR_string = 146;
        TransactionDataFormat[key].POS_valueR_string=274;
        TransactionDataFormat[key].POS_transactionNumber_string=290;
        TransactionDataFormat[key].POS_feed_string=294;
        TransactionDataFormat[key].POS_signature_string=302;
        TransactionDataFormat[key].POS_hidden_string=302;
        TransactionDataFormat[key].POS_signatureWithHidden_string=494;

    //length of bytes elements

        TransactionDataFormat[key].size_address_Bytes = 64;
        TransactionDataFormat[key].size_value_Bytes = 8;
        TransactionDataFormat[key].size_transactionNumber_Bytes = 2;
        TransactionDataFormat[key].size_feed_Bytes=4;
        TransactionDataFormat[key].size_signature_Bytes=64;
        TransactionDataFormat[key].size_hidden_Bytes=96;
        TransactionDataFormat[key].size_TransactionWithsignWoHidden_Bytes=215;
        TransactionDataFormat[key].size_TransactionOnlyData_Bytes=247;
        TransactionDataFormat[key].size_fullTransaction_Bytes=311;

    //length of string elements

        TransactionDataFormat[key].size_address_string = 128;
        TransactionDataFormat[key].size_value_string = 16;
        TransactionDataFormat[key].size_transactionNumber_string = 4;
        TransactionDataFormat[key].size_feed_string=8;
        TransactionDataFormat[key].size_signature_string=128;
        TransactionDataFormat[key].size_hidden_string=192;
        TransactionDataFormat[key].size_fullTransaction_String= 622;
    
}

void DataTransacFormatTypeInstance0x0A(std::unordered_map<uint8_t, TransactionElements>& TransactionDataFormat, uint8_t key){

    TransactionDataFormat[key].haveAccR = false;

    TransactionDataFormat[key].POS_transactionNumber_Bytes=1;
    TransactionDataFormat[key].POS_addressL_Bytes = 3; 
    TransactionDataFormat[key].POS_valueL_Bytes=67;
    TransactionDataFormat[key].POS_valueR_Bytes=75;
    TransactionDataFormat[key].POS_transactionValue_Bytes = 75;
    TransactionDataFormat[key].POS_feed_Bytes = 75;
    TransactionDataFormat[key].POS_Msg32bytes_Bytes = 83;
    TransactionDataFormat[key].POS_metadaPostAcc_Bytes = 83;
    TransactionDataFormat[key].POS_signature_Bytes=115;
    TransactionDataFormat[key].POS_hidden_Bytes=115;

    // position string

    TransactionDataFormat[key].POS_transactionNumber_string=2;
    TransactionDataFormat[key].POS_addressL_string = 6; 
    TransactionDataFormat[key].POS_valueL_string=134;
    TransactionDataFormat[key].POS_transactionValue_string = 150;
    TransactionDataFormat[key].POS_feed_string = 150;
    TransactionDataFormat[key].POS_Msg32bytes_string = 166;
    TransactionDataFormat[key].POS_signature_string=230;
    TransactionDataFormat[key].POS_hidden_string=230;
    TransactionDataFormat[key].POS_signatureWithHidden_string=422;

    //length of bytes elements

    TransactionDataFormat[key].size_transactionNumber_Bytes = 2;
    TransactionDataFormat[key].size_address_Bytes=64;
    TransactionDataFormat[key].size_value_Bytes=8;
    TransactionDataFormat[key].size_feed_Bytes=8;
    TransactionDataFormat[key].size_Msg32bytes_Bytes = 32;
    TransactionDataFormat[key].size_hidden_Bytes=96;
    TransactionDataFormat[key].size_signature_Bytes=64;
    TransactionDataFormat[key].size_TransactionWithsignWoHidden_Bytes=179;
    TransactionDataFormat[key].size_TransactionOnlyData_Bytes=211;
    TransactionDataFormat[key].size_fullTransaction_Bytes=275;
    
    //length of string elements

    TransactionDataFormat[key].size_transactionNumber_string = 4;
    TransactionDataFormat[key].size_Msg32bytes_string = 64;
    TransactionDataFormat[key].size_address_string=128;
    TransactionDataFormat[key].size_value_string=16;
    TransactionDataFormat[key].size_feed_string=16;
    TransactionDataFormat[key].size_hidden_string=192;
    TransactionDataFormat[key].size_signature_string=128;
    TransactionDataFormat[key].size_TransactionWithsignWoHidden_string=358;
    TransactionDataFormat[key].size_fullTransaction_String= 550;

}

void DataTransacFormatTypeInstance0x0C(std::unordered_map<uint8_t, TransactionElements>& TransactionDataFormat, uint8_t key){

    TransactionDataFormat[key].haveAccR = false;

    TransactionDataFormat[key].POS_transactionNumber_Bytes=1;
    TransactionDataFormat[key].POS_addressL_Bytes = 3; 
    TransactionDataFormat[key].POS_valueL_Bytes=67;
    TransactionDataFormat[key].POS_transactionValue_Bytes = 67;
    TransactionDataFormat[key].POS_feed_Bytes = 67;
    TransactionDataFormat[key].POS_Msg32bytes_Bytes = 75;
    TransactionDataFormat[key].POS_metadaPostAcc_Bytes = 75;
    TransactionDataFormat[key].POS_signature_Bytes=107;
    TransactionDataFormat[key].POS_hidden_Bytes=107;

    // position string

    TransactionDataFormat[key].POS_transactionNumber_string=2;
    TransactionDataFormat[key].POS_addressL_string = 6; 
    TransactionDataFormat[key].POS_valueL_string=134;
    TransactionDataFormat[key].POS_transactionValue_string = 134;
    TransactionDataFormat[key].POS_feed_string = 134;
    TransactionDataFormat[key].POS_Msg32bytes_string = 150;
    TransactionDataFormat[key].POS_signature_string=214;
    TransactionDataFormat[key].POS_hidden_string=214;
    TransactionDataFormat[key].POS_signatureWithHidden_string=406;

    //length of bytes elements

    TransactionDataFormat[key].size_transactionNumber_Bytes = 2;
    TransactionDataFormat[key].size_address_Bytes=64;
    TransactionDataFormat[key].size_value_Bytes=8;
    TransactionDataFormat[key].size_feed_Bytes=8;
    TransactionDataFormat[key].size_Msg32bytes_Bytes = 32;
    TransactionDataFormat[key].size_hidden_Bytes=96;
    TransactionDataFormat[key].size_signature_Bytes=64;
    TransactionDataFormat[key].size_TransactionWithsignWoHidden_Bytes=171;
    TransactionDataFormat[key].size_TransactionOnlyData_Bytes=203;
    TransactionDataFormat[key].size_fullTransaction_Bytes=267;
    
    //length of string elements

    TransactionDataFormat[key].size_transactionNumber_string = 4;
    TransactionDataFormat[key].size_Msg32bytes_string = 64;
    TransactionDataFormat[key].size_address_string=128;
    TransactionDataFormat[key].size_value_string=16;
    TransactionDataFormat[key].size_feed_string=16;
    TransactionDataFormat[key].size_hidden_string=192;
    TransactionDataFormat[key].size_signature_string=128;
    TransactionDataFormat[key].size_TransactionWithsignWoHidden_string=358;
    TransactionDataFormat[key].size_fullTransaction_String= 534;

}

inline std::unordered_map<uint8_t, TransactionElements> TransactionDataFormat;
inline unordered_map<uint8_t, uint8_t> CompressionBytesSize = CompressionBytesSizeInstance();

void instanceElementsTransaction(){

    DataTransacFormatTypeInstance0x00(TransactionDataFormat, 0x00);
    TransactionDataFormat[0x00].IsConfirmed = true;
    TransactionDataFormat[0x00].ValLIsDef = true;
    DataTransacFormatTypeInstance0x00(TransactionDataFormat, 0x02);
    TransactionDataFormat[0x02].IsConfirmed = false;
    TransactionDataFormat[0x02].ValLIsDef = true;
    DataTransacFormatTypeInstance0x00(TransactionDataFormat, 0x03);
    TransactionDataFormat[0x03].IsConfirmed = false;
    DataTransacFormatTypeInstance0x00(TransactionDataFormat, 0x04);
    TransactionDataFormat[0x04].IsConfirmed = true;
    DataTransacFormatTypeInstance0x00(TransactionDataFormat, 0x05);
    TransactionDataFormat[0x05].IsConfirmed = false;
    TransactionDataFormat[0x05].ValLIsDef = true;
    DataTransacFormatTypeInstance0x00(TransactionDataFormat, 0x06);
    TransactionDataFormat[0x06].IsConfirmed = true;
    TransactionDataFormat[0x06].ValLIsDef = true;
    DataTransacFormatTypeInstance0x00(TransactionDataFormat, 0x07);
    TransactionDataFormat[0x07].IsConfirmed = false;
    TransactionDataFormat[0x07].ValRIsDef = true;
    DataTransacFormatTypeInstance0x00(TransactionDataFormat, 0x08);
    TransactionDataFormat[0x08].IsConfirmed = true;
    TransactionDataFormat[0x08].ValRIsDef = true;
    DataTransacFormatTypeInstance0x0A(TransactionDataFormat, 0x09);
    TransactionDataFormat[0x09].IsConfirmed = false;
    TransactionDataFormat[0x09].ValLIsDef = true;
    DataTransacFormatTypeInstance0x0A(TransactionDataFormat, 0x0A);
    TransactionDataFormat[0x0A].IsConfirmed = true;
    TransactionDataFormat[0x0A].ValLIsDef = true;
    DataTransacFormatTypeInstance0x0C(TransactionDataFormat,0x0B);
    TransactionDataFormat[0x0B].IsConfirmed = false;
    TransactionDataFormat[0x0B].ValRIsDef = true;
    DataTransacFormatTypeInstance0x0C(TransactionDataFormat,0x0C);
    TransactionDataFormat[0x0C].IsConfirmed = true;
    TransactionDataFormat[0x0C].ValRIsDef = true;

}


#endif
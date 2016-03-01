//
//  HKRSA.h
//  RSADemo
//
//  Created by heke on 11/12/15.
//  Copyright © 2015年 mhk. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, HKAbstractType){
    //MD
    HKAbstractType_MD2,
//    HKAbstractType_MD4,//不能用于签名、验证操作
    HKAbstractType_MD5,
    
    //SHA
    HKAbstractType_SHA1,
    HKAbstractType_SHA224,
    HKAbstractType_SHA256,
    HKAbstractType_SHA384,
    HKAbstractType_SHA512
};

@interface HKRSA : NSObject

- (instancetype)sharedInstance;

- (void)loadPKFromFile:(NSString *)PKFilePath;
- (void)loadSKFromFile:(NSString *)SKFilePath password:(NSString *)password;

- (void)loadPKFromData:(NSData *)PKData;
- (void)loadSKFromData:(NSData *)SKData password:(NSString *)password;

- (NSString *)encryptString:(NSString *)rawString;
- (NSString *)decryptString:(NSString *)encryptedString;

- (NSString *)signString:(NSString *)rawString withAbstractType:(HKAbstractType)type;
- (BOOL)verifyString:(NSString *)rawString withSignature:(NSString *)signature  withAbstractType:(HKAbstractType)type;

//后续添加NSData的加密、解密、签名、签名验证等操作
@end


/**
 
 openssl genrsa -out private_key.pem 1024
 
 openssl req -new -key private_key.pem -out rsaCertReq.csr
 
 openssl x509 -req -days 3650 -in rsaCertReq.csr -signkey private_key.pem -out rsaCert.crt
 
 openssl x509 -outform der -in rsaCert.crt -out public_key.der　　　　　　　　　　　　　　　// Create public_key.der For IOS
 
 openssl pkcs12 -export -out private_key.p12 -inkey private_key.pem -in rsaCert.crt　　// Create private_key.p12 For IOS. 这一步，请记住你输入的密码，IOS代码里会用到
 
 openssl rsa -in private_key.pem -out rsa_public_key.pem -pubout　　　　　　　　　　　　　// Create rsa_public_key.pem For Java
 　
 openssl pkcs8 -topk8 -in private_key.pem -out pkcs8_private_key.pem -nocrypt　　　　　// Create pkcs8_private_key.pem For Java
 
 */

/*
 --x509:https://en.wikipedia.org/wiki/X.509
 --pkcs12:https://en.wikipedia.org/wiki/PKCS_12
 */

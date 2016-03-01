//
//  HKRSA.m
//  RSADemo
//
//  Created by heke on 11/12/15.
//  Copyright © 2015年 mhk. All rights reserved.

#import "HKRSA.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

static NSString *base64_encode_data(NSData *data){
    data = [data base64EncodedDataWithOptions:0];
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}

static NSData *base64_decode(NSString *str){
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return data;
}

@interface HKRSA () {
    SecKeyRef PK;
    SecKeyRef SK;
}

@end

@implementation HKRSA

- (void)dealloc{
    CFRelease(PK);
    CFRelease(SK);
}

- (instancetype)sharedInstance {
    static HKRSA *hkRSA = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        if (!hkRSA) {
            hkRSA = [[HKRSA alloc] init];
        }
    });
    return hkRSA;
}

- (void)loadPKFromFile:(NSString *)PKFilePath {
    NSData *PKData = [[NSData alloc] initWithContentsOfFile:PKFilePath];
    if ([PKData length]<1) {
        NSLog(@"PK load failed.... exit");
        return;
    }
    [self loadPKFromData:PKData];
}
- (void)loadSKFromFile:(NSString *)SKFilePath password:(NSString *)password {
    NSData *SKData = [[NSData alloc] initWithContentsOfFile:SKFilePath];
    if ([SKData length]<1) {
        NSLog(@"SK load failed.... exit");
        return;
    }
    [self loadSKFromData:SKData password:password];
}

- (void)loadPKFromData:(NSData *)PKData {
    if ([PKData length]<1) {
        NSLog(@"PK load failed.... exit");
        return;
    }
    PK = [self getPKRefrenceFromData:PKData];
}
- (void)loadSKFromData:(NSData *)SKData password:(NSString *)password {
    if ([SKData length]<1) {
        NSLog(@"SK load failed.... exit");
        return;
    }
    SK = [self getSKRefrenceFromData:SKData password:password];
}

- (SecKeyRef)getPK {
    return PK;
}

- (SecKeyRef)getSK {
    return SK;
}

- (NSString *)encryptString:(NSString *)rawString {
    NSData *data = [rawString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encryptedData = [self encryptData:data];
    return base64_encode_data(encryptedData);
}
- (NSString *)decryptString:(NSString *)encryptedString {
    NSData *data = base64_decode(encryptedString);
    NSData *rawData = [self decryptData:data];
    return [[NSString alloc] initWithData:rawData encoding:NSUTF8StringEncoding];
}

- (NSData *)encryptData:(NSData *)data {
    SecKeyRef key = [self getPK];
    size_t cipherBufferSize = SecKeyGetBlockSize(key);
    uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    size_t blockSize = cipherBufferSize - 11;
    size_t blockCount = (size_t)ceil([data length] / (double)blockSize);
    NSMutableData *encryptedData = [[NSMutableData alloc] init] ;
    for (int i=0; i<blockCount; i++) {
        NSInteger bufferSize = MIN(blockSize,[data length] - i * blockSize);
        NSData *buffer = [data subdataWithRange:NSMakeRange(i * blockSize, bufferSize)];
        OSStatus status = SecKeyEncrypt(key, kSecPaddingPKCS1, (const uint8_t *)[buffer bytes], [buffer length], cipherBuffer, &cipherBufferSize);
        if (status == noErr){
            NSData *encryptedBytes = [[NSData alloc] initWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
            [encryptedData appendData:encryptedBytes];
        }else{
            if (cipherBuffer) {
                free(cipherBuffer);
            }
            return nil;
        }
    }
    if (cipherBuffer){
        free(cipherBuffer);
    }
    return encryptedData;
}

- (NSData *)decryptData:(NSData *)data {
    SecKeyRef key = [self getSK];
    size_t cipherLen = [data length];
    void *cipher = malloc(cipherLen);
    [data getBytes:cipher length:cipherLen];
    size_t plainLen = SecKeyGetBlockSize(key) - 12;
    void *plain = malloc(plainLen);
    OSStatus status = SecKeyDecrypt(key, kSecPaddingPKCS1, cipher, cipherLen, plain, &plainLen);
    
    if (status != noErr) {
        return nil;
    }
    
    NSData *decryptedData = [[NSData alloc] initWithBytes:(const void *)plain length:plainLen];
    
    return decryptedData;
}

- (NSString *)signString:(NSString *)rawString withAbstractType:(HKAbstractType)type {
    NSData *data = [rawString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *tempData = [HKRSA abstractOfData:data withType:type];
    NSData *vData = [self signData:tempData withPadding:[HKRSA secPaddingWithType:type]];
    return base64_encode_data(vData);
}

- (BOOL)verifyString:(NSString *)rawString withSignature:(NSString *)signature  withAbstractType:(HKAbstractType)type {
    NSData *vData = base64_decode(signature);
    NSData *rawData = [rawString dataUsingEncoding:NSUTF8StringEncoding];
    return [self verifyData:[HKRSA abstractOfData:rawData withType:type] withSignature:vData withPadding:[HKRSA secPaddingWithType:type]];
}

- (NSData *)signData:(NSData *)rawData withPadding:(SecPadding)padding{
    size_t hashSize = SecKeyGetBlockSize([self getSK]);
    uint8_t *bytes = malloc(hashSize);
    
    OSStatus err = SecKeyRawSign([self getSK],
                                 padding,
                                 [rawData bytes],
                                 [rawData length],
                                 bytes,
                                 &hashSize);
    NSAssert(err == errSecSuccess, @"SecKeyRawSign failed: %d", (int)err);
    
    return [NSData dataWithBytesNoCopy:bytes length:hashSize];
    return nil;
}
- (BOOL)verifyData:(NSData *)rawData withSignature:(NSData *)signature  withPadding:(SecPadding)padding{
    return errSecSuccess == SecKeyRawVerify([self getPK],
                                            padding,
                                            [rawData bytes],
                                            [rawData length],
                                            [signature bytes],
                                            [signature length]);
}

#pragma mark - private methods
- (SecKeyRef)getPKRefrenceFromData: (NSData*)PKData {
    
    SecCertificateRef PKCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)PKData);
    SecPolicyRef myPolicy = SecPolicyCreateBasicX509();
    SecTrustRef myTrust;
    OSStatus status = SecTrustCreateWithCertificates(PKCertificate,myPolicy,&myTrust);
    SecTrustResultType trustResult;
    if (status == noErr) {
        status = SecTrustEvaluate(myTrust, &trustResult);
    }
    SecKeyRef tempPK = SecTrustCopyPublicKey(myTrust);
    CFRelease(PKCertificate);
    CFRelease(myPolicy);
    CFRelease(myTrust);
    
    return tempPK;
}

- (SecKeyRef)getSKRefrenceFromData: (NSData*)SKData password:(NSString*)password{
    SecKeyRef tempSK = NULL;
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init];
    [options setObject: password forKey:(__bridge id)kSecImportExportPassphrase];
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus securityError = SecPKCS12Import((__bridge CFDataRef)SKData, (__bridge CFDictionaryRef)options, &items);
    if (securityError == noErr && CFArrayGetCount(items) > 0) {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
        securityError = SecIdentityCopyPrivateKey(identityApp, &tempSK);
        if (securityError != noErr) {
            tempSK = NULL;
        }
    }
    CFRelease(items);
    
    return tempSK;
}

+ (NSData *)abstractOfData:(NSData *)rawData withType:(HKAbstractType)abstractType {
    size_t hashBytesSize = [HKRSA abstractLengthWithType:abstractType];
    uint8_t* hashBytes = malloc(hashBytesSize);
    unsigned char * (*func)(const void *data, CC_LONG len, unsigned char *md)  = [HKRSA abstractFunctionWithType:abstractType];
    
    if (!func([rawData bytes], (CC_LONG)[rawData length], hashBytes)) {
        return nil;
    }else{
        return [NSData dataWithBytes:hashBytes length:hashBytesSize];
    }
}

+ (size_t)abstractLengthWithType:(HKAbstractType)type {
    switch (type) {
        case HKAbstractType_MD2:
            return CC_MD2_DIGEST_LENGTH;
            break;
        case HKAbstractType_MD5:
            return CC_MD5_DIGEST_LENGTH;
            break;
        case HKAbstractType_SHA1:
            return CC_SHA1_DIGEST_LENGTH;
            break;
        case HKAbstractType_SHA224:
            return CC_SHA224_DIGEST_LENGTH;
            break;
        case HKAbstractType_SHA256:
            return CC_SHA256_DIGEST_LENGTH;
            break;
        case HKAbstractType_SHA384:
            return CC_SHA384_DIGEST_LENGTH;
            break;
        case HKAbstractType_SHA512:
            return CC_SHA512_DIGEST_LENGTH;
            break;
            
        default:
            break;
    }
    return 0;
}

+ (unsigned char * (*)(const void *data, CC_LONG len, unsigned char *md))abstractFunctionWithType:(HKAbstractType)type {
    switch (type) {
        case HKAbstractType_MD2:
            return CC_MD2;
            break;
        case HKAbstractType_MD5:
            return CC_MD5;
            break;
        case HKAbstractType_SHA1:
            return CC_SHA1;
            break;
        case HKAbstractType_SHA224:
            return CC_SHA224;
            break;
        case HKAbstractType_SHA256:
            return CC_SHA256;
            break;
        case HKAbstractType_SHA384:
            return CC_SHA384;
            break;
        case HKAbstractType_SHA512:
            return CC_SHA512;
            break;
            
        default:
            break;
    }
    return NULL;
}

+ (SecPadding)secPaddingWithType:(HKAbstractType)type {
    switch (type) {
        case HKAbstractType_MD2:
            return kSecPaddingPKCS1MD2;
            break;
        case HKAbstractType_MD5:
            return kSecPaddingPKCS1MD5;
            break;
        case HKAbstractType_SHA1:
            return kSecPaddingPKCS1SHA1;
            break;
        case HKAbstractType_SHA224:
            return kSecPaddingPKCS1SHA224;
            break;
        case HKAbstractType_SHA256:
            return kSecPaddingPKCS1SHA256;
            break;
        case HKAbstractType_SHA384:
            return kSecPaddingPKCS1SHA384;
            break;
        case HKAbstractType_SHA512:
            return kSecPaddingPKCS1SHA512;
            break;
            
        default:
            break;
    }
    return kSecPaddingNone;
}

@end

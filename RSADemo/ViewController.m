//
//  ViewController.m
//  RSADemo
//
//  Created by heke on 11/12/15.
//  Copyright © 2015年 mhk. All rights reserved.
//

#import "ViewController.h"
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>
#import "HKRSA.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [self test];
}

- (void)test {
    HKRSA *rsa = [HKRSA sharedInstance];
    [rsa loadPKFromFile:[[NSBundle mainBundle] pathForResource:@"public_key" ofType:@"der"]];
    [rsa loadSKFromFile:[[NSBundle mainBundle] pathForResource:@"private_key" ofType:@"p12"] password:@"123456"];
    NSString *rawString = @"CFNumberRef keySize = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &iKeySize);";
    NSString *encryString = [rsa encryptString:rawString];
    NSString *decryptString = [rsa decryptString:encryString];
    if (![rawString isEqualToString:decryptString]) {
        NSLog(@"加解密 failed");
    }
    
    NSString *signedString = [rsa signString:rawString withAbstractType:HKAbstractType_SHA384];
    BOOL result = [rsa verifyString:rawString withSignature:signedString withAbstractType:HKAbstractType_SHA384];
    if (!result) {
        NSLog(@"签名 failed");
    }
}

@end

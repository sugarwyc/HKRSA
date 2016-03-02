# HKRSA
用OC封装系统提供的接口实现RSA加密、解密、签名、验证

## Installation with CocoaPods

[CocoaPods](http://cocoapods.org) is a dependency manager for Objective-C, which automates and simplifies the process of using 3rd-party libraries like HKRSA in your projects. You can install it with the following command:

```bash
$ gem install cocoapods
```

#### Podfile

To integrate HKRSA into your Xcode project using CocoaPods, specify it in your `Podfile`:

```ruby
source 'https://github.com/CocoaPods/Specs.git'
platform :ios, '7.0'

pod 'HKRSA'
```

Then, run the following command:

```bash
$ pod install
```

####USAGE
#####加密、解密
```objective-c
    HKRSA *rsa = [HKRSA sharedInstance];
    [rsa loadPKFromFile:[[NSBundle mainBundle] pathForResource:@"public_key" ofType:@"der"]];
    [rsa loadSKFromFile:[[NSBundle mainBundle] pathForResource:@"private_key" ofType:@"p12"] password:@"123456"];
	
    NSString *rawString = @"CFNumberRef keySize = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &iKeySize);";
    NSString *encryString = [rsa encryptString:rawString];
    NSString *decryptString = [rsa decryptString:encryString];
    if (![rawString isEqualToString:decryptString]) {
        NSLog(@"加解密 failed");
    }
```

#####签名、验证
```objective-c
    HKRSA *rsa = [HKRSA sharedInstance];
    [rsa loadPKFromFile:[[NSBundle mainBundle] pathForResource:@"public_key" ofType:@"der"]];
    [rsa loadSKFromFile:[[NSBundle mainBundle] pathForResource:@"private_key" ofType:@"p12"] password:@"123456"];
	
    NSString *rawString = @"CFNumberRef keySize = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &iKeySize);";    
    NSString *signedString = [rsa signString:rawString withAbstractType:HKAbstractType_SHA384];
    BOOL result = [rsa verifyString:rawString withSignature:signedString withAbstractType:HKAbstractType_SHA384];
    if (!result) {
        NSLog(@"签名 failed");
    }
```

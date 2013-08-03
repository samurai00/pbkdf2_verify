//
//  PBKDF2.m
//  pbkdf2
//
//  Created by afon on 13-8-3.
//  Copyright (c) 2013年 afon. All rights reserved.
//

#import "PBKDF2.h"
#import "Base64.h"

@implementation PBKDF2

+ (NSData *)pbkdf2:(NSString *)password salt:(NSString *) s count:(int) c kLen:(int) l withAlgo:(AlgoType)algo
{
    unsigned char key[l];
    CCKeyDerivationPBKDF(kCCPBKDF2, [password UTF8String], [password length], (const unsigned char *)[s UTF8String], [s length], algo, c, key, l);
    return [NSData dataWithBytes:key length:l];
}

+ (NSData *)pbkdf2:(NSString *)password salt:(NSString *) s count:(int) c kLen:(int) l
{
    return [self pbkdf2:password salt:s count:c kLen:l withAlgo:kSHA256];
}

+ (NSString *)pass_hash:(NSString *) password length:(int) l count:(int) c saltLength:(int)sl
{
    NSString *s = [self rand_str:sl];
    NSData *hash_data = [self pbkdf2:password salt:s count:c kLen:l];
    return [NSString stringWithFormat:@"$%02d$%02d$%@%@", c/1000, l, s, [hash_data base64EncodedString]];
}

+ (NSString *)pass_hash:(NSString *) password length:(int) l count:(int) c
{
    return [self pass_hash:password length:l count:c saltLength:20];
}

+ (NSString *)pass_hash:(NSString *) password length:(int) l
{
    return [self pass_hash:password length:l count:10000];
}

+ (NSString *)pass_hash:(NSString *) password
{
    return [self pass_hash:password length:32 count:10000];
}

+ (BOOL)pass_verify:(NSString *) password hash:(NSString *) h
{
    NSArray *p = [[h substringFromIndex:1] componentsSeparatedByString:@"$"];
    NSString *salt_hash = [p objectAtIndex:2];
    int salt_len = [salt_hash length] - (int)ceil([[p objectAtIndex:1] doubleValue]/3) * 4;
    NSString *encoded_hash = [[self pbkdf2:password salt:[salt_hash substringToIndex: salt_len] count:[[p objectAtIndex:0] intValue]*1000 kLen:[[p objectAtIndex:1] intValue]] base64EncodedString];
    if ([encoded_hash isEqualToString:[salt_hash substringFromIndex:salt_len]]) {
        return YES;
    } else {
        return NO;
    }
}

+ (NSString *) rand_str:(int) l
{
    char pool[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char data[l];
    for (int x=0;x<l;data[x++] = (char)(pool[arc4random_uniform(62)]));
    return [[NSString alloc] initWithBytes:data length:l encoding:NSUTF8StringEncoding];
}

@end

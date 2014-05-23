//
//  Keychain.h
//  Keychain
//
//  Created by Collin B. Stuart on 2014-05-14.
//  Copyright (c) 2014 CollinBStuart. All rights reserved.
//

#import <Foundation/Foundation.h>

/** string domain for keychain */
extern CFStringRef kKeychainServiceErrorDomain;

/** OSStatus Error codes from SecBase.h with the addition of a few error codes, inspired by SSKeychain */
CF_ENUM(OSStatus, KeychainErrorCode)
{
    /** No error. */
    KeychainErrorNone = errSecSuccess,
    
    /** Some of the arguments were invalid. */
    KeychainErrorBadArguments = -1001,
    
    /** There was no password. */
    KeychainErrorNoPassword = -1002,
    
    /** One or more parameters passed internally were not valid. */
    KeychainErrorInvalidParameter = errSecParam,
    
    /** Failed to allocate memory. */
    KeychainErrorFailedToAllocated = errSecAllocate,
    
    /** No trust results are available. */
    KeychainErrorNotAvailable = errSecNotAvailable,
    
    /** Authorization/Authentication failed. */
    KeychainErrorAuthorizationFailed = errSecAuthFailed,
    
    /** The item already exists. */
    KeychainErrorDuplicatedItem = errSecDuplicateItem,
    
    /** The item cannot be found.*/
    KeychainErrorNotFound = errSecItemNotFound,
    
    /** Interaction with the Security Server is not allowed. */
    KeychainErrorInteractionNotAllowed = errSecInteractionNotAllowed,
    
    /** Unable to decode the provided data. */
    KeychainErrorFailedToDecode = errSecDecode
};

/** Returns a password string for the passed in keychain name and item. If the item is not found, returns NULL. */
CFStringRef KeychainPasswordForKeychainItem(CFStringRef serviceString, CFStringRef accountString, CFErrorRef *error);

/** Deletes a password from the Keychain. */
Boolean KeychainDeletePasswordForKeychainItem(CFStringRef serviceString, CFStringRef accountString, CFErrorRef *error);

/** Sets a password in the Keychain. */
Boolean KeychainSetPassword(CFStringRef passwordString, CFStringRef serviceString, CFStringRef accountString, CFErrorRef *error);
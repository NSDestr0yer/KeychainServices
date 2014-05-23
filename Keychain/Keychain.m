//
//  Keychain.m
//  Keychain
//
//  Created by Collin B. Stuart on 2014-05-14.
//  Copyright (c) 2014 CollinBStuart. All rights reserved.
//

#import "Keychain.h"
#import <Security/Security.h>

CFStringRef kKeychainServiceErrorDomain = CFSTR("com.testproject.keychain");

CFMutableDictionaryRef _QueryDictionaryForService(CFStringRef serviceString, CFStringRef accountString)
{
    //return a dictionaty containing the key-value pairs for use with adding to keychain services
    CFMutableDictionaryRef mutableDictionary = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(mutableDictionary, kSecClass, kSecClassGenericPassword);
    CFDictionaryAddValue(mutableDictionary, kSecAttrAccount, accountString);
    CFDictionaryAddValue(mutableDictionary, kSecAttrService, serviceString);
    CFDictionaryAddValue(mutableDictionary, kSecAttrAccessible, kSecAttrAccessibleWhenUnlocked); // accessable only when unlocked
    
	return (CFMutableDictionaryRef)CFAutorelease(mutableDictionary);
}

CFStringRef KeychainPasswordForKeychainItem(CFStringRef serviceString, CFStringRef accountString, CFErrorRef *error)
{
	OSStatus status = KeychainErrorBadArguments;
	CFStringRef resultString = NULL;
	
	if (0 < CFStringGetLength(serviceString) && 0 < CFStringGetLength(accountString))
    {
		CFDataRef passwordData = NULL;
		CFMutableDictionaryRef keychainQueryDictionary = _QueryDictionaryForService(serviceString, accountString);
        
        if (keychainQueryDictionary)
        {
            CFDictionarySetValue(keychainQueryDictionary, kSecReturnData, kCFBooleanTrue);
            CFDictionarySetValue(keychainQueryDictionary, kSecMatchLimit, kSecMatchLimitOne);
            
            //returns -25308 if user happens to lock phone by the time this is called
            status = SecItemCopyMatching(keychainQueryDictionary, (CFTypeRef *)&passwordData);
        }
        
		if (status == noErr && 0 < CFDataGetLength(passwordData))
        {
			resultString = CFStringCreateWithBytes(kCFAllocatorDefault, CFDataGetBytePtr(passwordData), CFDataGetLength(passwordData), kCFStringEncodingUTF8, TRUE);
            CFAutorelease(resultString);
		}
		
		if (passwordData != NULL)
        {
			CFRelease(passwordData);
		}
	}
	
	if (status != noErr && error != NULL)
    {
		*error = CFErrorCreate(kCFAllocatorDefault, kKeychainServiceErrorDomain, status, NULL);
	}
	
	return resultString;
}

Boolean KeychainDeletePasswordForKeychainItem(CFStringRef serviceString, CFStringRef accountString, CFErrorRef *error)
{
	OSStatus status = KeychainErrorBadArguments;
	if (0 < CFStringGetLength(serviceString) && 0 < CFStringGetLength(accountString))
    {
		CFMutableDictionaryRef keychainQueryDictionary = _QueryDictionaryForService(serviceString, accountString);
		status = SecItemDelete(keychainQueryDictionary);
	}
	
	if (status != noErr && error != NULL)
    {
		*error = CFErrorCreate(kCFAllocatorDefault, kKeychainServiceErrorDomain, status, NULL);
	}
	
	return status == noErr;
}

Boolean KeychainSetPassword(CFStringRef passwordString, CFStringRef serviceString, CFStringRef accountString, CFErrorRef *error)
{
	OSStatus status = KeychainErrorBadArguments;
	if (0 < CFStringGetLength(serviceString) && 0 < CFStringGetLength(accountString))
    {
		KeychainDeletePasswordForKeychainItem(serviceString, accountString, NULL);
		if (0 < CFStringGetLength(passwordString))
        {
			CFMutableDictionaryRef keychainQueryDictionary = _QueryDictionaryForService(serviceString, accountString);
			CFDataRef passwordData = CFStringCreateExternalRepresentation(kCFAllocatorDefault, passwordString, kCFStringEncodingUTF8, 0);
            CFDictionarySetValue(keychainQueryDictionary, kSecValueData, passwordData);
			status = SecItemAdd(keychainQueryDictionary, NULL);
            CFRelease(passwordData);
		}
	}
	
	if (status != noErr && error != NULL)
    {
		*error = CFErrorCreate(kCFAllocatorDefault, kKeychainServiceErrorDomain, status, NULL);
	}
	
	return status == noErr;
}

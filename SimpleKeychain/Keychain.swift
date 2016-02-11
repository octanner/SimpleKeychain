//
//  Keychain.swift
//  falkor
//
//  Created by Tim Shadel on 11/10/15.
//  Copyright © 2016 OC Tanner. All rights reserved.
//

import Foundation


struct Keychain {

    enum Error: ErrorType {
        case NoValueForKey(String)
        case TypeMismatch(String)
        case KeychainError(String, OSStatus)
    }

    func valueForKey<A>(key: String) throws -> A {
        let query = [
            kSecClass as String       : kSecClassGenericPassword,
            kSecAttrAccount as String : key,
            kSecReturnData as String  : kCFBooleanTrue,
            kSecMatchLimit as String  : kSecMatchLimitOne ]

        var dataTypeRef: AnyObject?
        let status = withUnsafeMutablePointer(&dataTypeRef) { SecItemCopyMatching(query, UnsafeMutablePointer($0)) }

        if status == errSecSuccess {
            if let data = dataTypeRef as? NSData {
                let object = NSKeyedUnarchiver.unarchiveObjectWithData(data)
                if let value = object as? A {
                    return value
                } else {
                    throw Error.TypeMismatch(key)
                }
            } else {
                throw Error.TypeMismatch(key)
            }
        } else if status == errSecItemNotFound {
            throw Error.NoValueForKey(key)
        } else {
            throw Error.KeychainError(key, status)
        }
    }

    func optionalForKey<A>(key: String) throws -> A? {
        do {
            let a: A = try valueForKey(key)
            return a
        }
        catch Error.NoValueForKey {
            return nil
        }
        catch {
            throw Error.TypeMismatch(key)
        }
    }

    func set(value: NSCoding, forKey key: String) throws {
        let data = NSKeyedArchiver.archivedDataWithRootObject(value)
        let query = [
            kSecClass as String       : kSecClassGenericPassword as String,
            kSecAttrAccount as String : key,
            kSecValueData as String   : data ]

        SecItemDelete(query as CFDictionaryRef)

        let status: OSStatus = SecItemAdd(query as CFDictionaryRef, nil)

        if status != noErr {
            throw Error.KeychainError(key, status)
        }
    }

    func deleteValue(forKey key: String) {
        let query = [
            kSecClass as String       : kSecClassGenericPassword as String,
            kSecAttrAccount as String : key ]

        SecItemDelete(query as CFDictionaryRef)
    }
    
}

//
//  Keychain.swift
//  SimpleKeychain
//
//  Created by Tim Shadel on 11/10/15.
//  Copyright © 2016 OC Tanner. All rights reserved.
//

import Foundation


public struct Keychain {

    public enum KeychainError: Error {
        case noValueForKey(String)
        case typeMismatch(String)
        case keychainError(String, OSStatus)
    }

    public let group: String?

    public init(group: String? = nil) {
        self.group = group
    }

    // Lookups will search all keychains, in order.
    public func valueForKey<A>(_ key: String) throws -> A {
        let query = [
            kSecClass as String       : kSecClassGenericPassword,
            kSecAttrAccount as String : key,
            kSecReturnData as String  : kCFBooleanTrue,
            kSecMatchLimit as String  : kSecMatchLimitOne ] as [String : Any]

        var dataTypeRef: AnyObject?
        let status = withUnsafeMutablePointer(to: &dataTypeRef) { SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0)) }

        if status == errSecSuccess {
            if let data = dataTypeRef as? Data {
                let object = NSKeyedUnarchiver.unarchiveObject(with: data)
                if let value = object as? A {
                    return value
                } else {
                    throw KeychainError.typeMismatch(key)
                }
            } else {
                throw KeychainError.typeMismatch(key)
            }
        } else if status == errSecItemNotFound {
            throw KeychainError.noValueForKey(key)
        } else {
            throw KeychainError.keychainError(key, status)
        }
    }

    public func optionalForKey<A>(_ key: String) throws -> A? {
        do {
            let a: A = try valueForKey(key)
            return a
        }
        catch KeychainError.noValueForKey {
            return nil
        }
        catch {
            throw KeychainError.typeMismatch(key)
        }
    }

    public func set(_ value: NSCoding, forKey key: String) throws {
        let data = NSKeyedArchiver.archivedData(withRootObject: value)
        var query = [
            kSecClass as String       : kSecClassGenericPassword as String,
            kSecAttrAccount as String : key,
            kSecValueData as String   : data ] as [String : Any]

        // Delete will go through all access groups
        SecItemDelete(query as CFDictionary)

        // Add to only one access group
        if let group = group {
            query[kSecAttrAccessGroup as String] = group
        }
        let status: OSStatus = SecItemAdd(query as CFDictionary, nil)

        if status != noErr {
            throw KeychainError.keychainError(key, status)
        }
    }

    // Delete will go through all access groups
    public func deleteValue(forKey key: String) {
        let query = [
            kSecClass as String       : kSecClassGenericPassword as String,
            kSecAttrAccount as String : key ]
        
        SecItemDelete(query as CFDictionary)
    }
    
}

//
//  AES256.swift
//
//  Created by Tiago Almeida de Oliveira on 18/10/21.
//  Copyright © 2020. All rights reserved.
//

import CommonCrypto
import CryptoKit

protocol AES256Protocol {
    func encrypt(plainText text: String) throws -> String?
    func decrypt(cipherBase64Text text: String) throws -> String?
}

struct AES256: AES256Protocol {

    enum AES256Error: Swift.Error {
        case invalidKeySize
        case invalidInputVectorSize
        case convertStringToDataFailed
        case cryptoFailed(status: CCCryptorStatus)
        case keyGeneratorFailed(status: Int32)
    }

    private let options = CCOptions(kCCOptionPKCS7Padding)
    private let algorithm = CCAlgorithm(kCCAlgorithmAES128)
    private let ivData: Data
    private let keyData: Data
    
    init(key: String, iv: String) throws {
        guard let ivData = iv.data(using: .utf8),
              let keyData = key.data(using: .utf8) else {
            throw AES256Error.convertStringToDataFailed
        }
        guard keyData.count == kCCKeySizeAES256 else {
            throw AES256Error.invalidKeySize
        }
        guard ivData.count == kCCBlockSizeAES128 else {
            throw AES256Error.invalidInputVectorSize
        }
        self.ivData = ivData
        self.keyData = keyData
    }

    func encrypt(plainText text: String) throws -> String? {
        guard let input = text.data(using: .utf8) else {
            throw AES256Error.convertStringToDataFailed
        }
        let data = try crypt(input: input, operation: CCOperation(kCCEncrypt))
        return data.base64EncodedString()
    }

    func decrypt(cipherBase64Text base64Text: String) throws -> String? {
        guard let input = Data(base64Encoded: base64Text) else {
            throw AES256Error.convertStringToDataFailed
        }
        let data = try crypt(input: input, operation: CCOperation(kCCDecrypt))
        return String(data: data, encoding: .utf8)
    }

    private func crypt(input: Data, operation: CCOperation) throws ->  Data {

        var outLenght = Int.zero
        var outBytes = [UInt8](repeating: 0, count: input.count + kCCBlockSizeAES128)
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)

        input.withUnsafeBytes { rawPointer in
            let encBytes = rawPointer.baseAddress!

            ivData.withUnsafeBytes { rawPointer in
                let ivBytes = rawPointer.baseAddress!

                keyData.withUnsafeBytes { rawPointer in
                    let keyBytes = rawPointer.baseAddress!
                    status = CCCrypt(operation,
                                     algorithm,
                                     options,
                                     keyBytes,
                                     keyData.count,
                                     ivBytes,
                                     encBytes,
                                     input.count,
                                     &outBytes,
                                     outBytes.count,
                                     &outLenght)
                }
            }
        }

        guard status == kCCSuccess else {
            throw AES256Error.cryptoFailed(status: status)
        }

        return Data(bytes: &outBytes, count: outLenght)
    }

    static func createKey(password: String, salt: String) throws -> Data {
        guard let passwordData = password.data(using: .utf8), let saltData = salt.data(using: .utf8) else {
            throw AES256Error.convertStringToDataFailed
        }

        let lenght = kCCKeySizeAES256
        var status = Int32.zero
        var derivedBytes = [UInt8](repeating: 0, count: lenght)
        let kCreateKeyRounds = UInt32(10000)

        passwordData.withUnsafeBytes { rawPointer in
            let passwordRaw = rawPointer.baseAddress!
            let passwordBytes = passwordRaw.assumingMemoryBound(to: Int8.self)
            
            saltData.withUnsafeBytes { rawPointer in
                let saltRaw = rawPointer.baseAddress!
                let saltBytes = saltRaw.assumingMemoryBound(to: UInt8.self)
                
                status = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                              passwordBytes, password.count,
                                              saltBytes, saltData.count,
                                              CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
                                              kCreateKeyRounds,
                                              &derivedBytes,
                                              lenght)
            }
        }

        guard status == 0 else {
            throw AES256Error.keyGeneratorFailed(status: status)
        }
        return Data(bytes: &derivedBytes, count: lenght)
    }
}

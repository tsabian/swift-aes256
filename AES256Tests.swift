//
//  AES256Tests.swift
//
//  Created by Tiago Almeida de Oliveira on 19/10/21.
//  Copyright © 2020. All rights reserved.
//

import XCTest
@testable import Project

class AES256Tests: XCTestCase {
    
    var sut: AES256Protocol!
    let plain = "teste"
    let cipher = "63Nx2I3LeBK4Ul90ox6wkg=="
    
    private let kSalt = "1A67C6C0"
    private let kKey = "A6EF9339E772CC3D7F32F84B9E81B33D"
    private let kIv = "5F583182638977A1"
    
    /*
    salt=3141363743364330
    key=4136454639333339453737324343334437463332463834423945383142333344
    iv=35463538333138323633383937374131
    */
    
    override func setUp() {
        super.setUp()
        do {
            sut = try AES256(key: kKey, iv: kIv)
        } catch let err {
            XCTFail("AES256 init did fail \(err.localizedDescription)")
        }
    }
    
    override func tearDown() {
        sut = nil
        super.tearDown()
    }
    
    func testCreateKey() {
        do {
            let randomKey = try AES256.createKey(password: "p@ss!_9876", salt: kSalt)
            XCTAssertTrue(!randomKey.isEmpty)
        } catch let err {
            print(err)
            XCTFail("CreateKey Failed")
        }
    }
    
    func testEncrypt() {
        var actual: String?
        do {
            actual = try sut.encrypt(plainText: plain)
            XCTAssertEqual(cipher, actual)
        } catch let err {
            XCTFail("Encrypt fail \(err.localizedDescription)")
        }
    }
    
    func testDecrypt() {
        var actual: String?
        do {
            actual = try sut.decrypt(cipherBase64Text: cipher)
            XCTAssertEqual(plain, actual)
        } catch let err {
            XCTFail("Decrypt fail \(err.localizedDescription)")
        }
    }
}

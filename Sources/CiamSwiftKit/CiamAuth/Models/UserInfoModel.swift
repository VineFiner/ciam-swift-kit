//
//  File.swift
//  
//
//  Created by Finer  Vine on 2021/11/30.
//

import Foundation
import OAuthSwiftCore

public struct UserInfoModel: AnyCodableModel {
    public let sub: String
    
    public let userName: String?
    public let name: String?
    public let phoneNumber: String?
    public let email: String?
    public let gender: String?
    public let address: String?
}

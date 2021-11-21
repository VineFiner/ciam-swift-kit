//
//  File.swift
//  
//
//  Created by Finer  Vine on 2021/11/22.
//

import Foundation
import OAuthSwiftCore

public struct CiamConfiguration: OAuthSwiftCore.APIConfiguration {
    
    public var scopes: [APIScope]

    public var userDomain: String
    public var redirectUri: String
    public var logoutRedirectUrl: String
    public var authType: CiamAuthType
    
    public init(scopes: [CiamAuthScope],
                userDomain: String,
                redirectUri: String,
                logoutRedirectUrl: String,
                authType: CiamAuthType? = nil) {
        self.scopes = scopes
        
        self.userDomain = userDomain
        self.redirectUri = redirectUri
        self.logoutRedirectUrl = logoutRedirectUrl
        self.authType = authType ?? .pkce
    }
}

public enum CiamAuthScope: APIScope {
    case openid
    
    public var value: String {
        switch self {
        case .openid:
            return "openid"
        }
    }
}

public enum CiamAuthType: String {
    case pkce = "OIDC_PKCE"
    case normal = "NORMAL"
}

//
//  File.swift
//  
//
//  Created by Finer  Vine on 2021/11/21.
//

import Foundation
import NIOCore
import NIOHTTP1
import Logging
import OAuthSwiftCore
import Crypto
import AsyncHTTPClient

/// Ciam 客户端
///
/// 可以使用证书和配置创建 客户端
///
/// ```swift
/// let ciamClient = CiamClient.init(credentials: self.credentials,
/// config: self.configuration,
/// httpClient: self.http,
/// eventLoop: self.eventLoop,
/// logger: self.logger)
///
/// let url = ciamClient.generateAuthUrl()
/// ```
public final class CiamClient {
    
    public var auth: CiamAuthAPI
    var ciamAuthrequest: CiamRequest
    let credentials: ApplicationDefaultCredentials
    let config: CiamConfiguration
    
    let code_verifier = UUID().uuidString
    
    /// 使用证书和配置初始化 Ciam Client
    ///
    /// - Parameters:
    ///   - credentials: 证书
    ///   - config: 配置
    ///   - httpClient: 客户端
    ///   - eventLoop: 用于执行工作的 Eventloop
    ///   - logger: 记录日志
    public init(credentials: ApplicationDefaultCredentials,
                config: CiamConfiguration,
                httpClient: HTTPClient,
                eventLoop: EventLoop,
                logger: Logger) {
        // 证书
        self.credentials = credentials
        // 配置
        self.config = config
        /// 刷新令牌。
        let refreshableToken = OAuthApplicationDefault(credentials: credentials,
                                                       httpClient: httpClient,
                                                       eventLoop: eventLoop)
        // 这里是请求
        ciamAuthrequest = CiamRequest(httpClient: httpClient, eventLoop: eventLoop, oauth: refreshableToken)
        // 这里是API
        auth = CiamAuthenticationAPI.init(endpoint: "\(self.config.userDomain)", request: ciamAuthrequest)
    }
    
    /// 跳到一个新的事件循环来执行请求。
    /// - 参数 eventLoop：在其上执行请求的事件循环。
    public func hopped(to eventLoop: EventLoop) -> CiamClient {
        ciamAuthrequest.eventLoop = eventLoop
        return self
    }
}

// MARK: 使用认证门户登录
extension CiamClient {
    /// 推荐使用 PKCE模式
    public func generateAuthUrl() -> String {
        return "\(self.config.userDomain)/oauth2/authorize?scope=openid&client_id=\(self.credentials.clientId)&redirect_uri=\(self.config.redirectUri)&response_type=code&code_challenge_method=S256&code_challenge=\(generateCodeChallenge(codeVerifier: code_verifier))"
    }
}
// MARK: 退出认证门户
extension CiamClient {
    // 执行 302 跳转
    public func ciamLogout(logoutRedirectUri: String? = nil) -> String {
        let logoutUri: String = "\(self.config.userDomain)/logout?client_id=\(self.credentials.clientId)&logout_redirect_uri=\(logoutRedirectUri ?? self.config.logoutRedirectUrl)"
        return logoutUri
    }
}
// MARK: 使用认证门户注册
extension CiamClient {
    public func generateRegisterUrl() -> String {
        return "\(self.config.userDomain)/oauth2/authorize?scope=openid&client_id=\(self.credentials.clientId)&redirect_uri=\(self.config.redirectUri)&response_type=code&code_challenge_method=S256&code_challenge=\(generateCodeChallenge(codeVerifier: code_verifier))&prompt=create"
    }
}
// MARK: 获取Token
extension CiamClient {
    /// 获取Token
    public func fetchToken(code: String) -> EventLoopFuture<OAuthAccessToken> {
        
        do {
            let headers: HTTPHeaders = ["Content-Type": "application/x-www-form-urlencoded"]
            
            let body: HTTPClient.Body = .string("client_id=\(credentials.clientId)&code=\(code)&redirect_uri=\(self.config.redirectUri)&code_verifier=\(code_verifier)&grant_type=authorization_code")
            
            let request = try HTTPClient.Request(url: credentials.tokenUri, method: .POST, headers: headers, body: body)
            
            return ciamAuthrequest.httpClient.execute(request: request, eventLoop: .delegate(on: ciamAuthrequest.eventLoop)).flatMap { response in
                
                guard var byteBuffer = response.body,
                      let responseData = byteBuffer.readData(length: byteBuffer.readableBytes),
                      response.status == .ok else {
                          let body = response.body?.getString(at: response.body?.readerIndex ?? 0, length: response.body?.readableBytes ?? 0) ?? ""
                          let error = CiamAuthError(error: CiamAuthAPIErrorBody(status: .unknownError, code: Int(response.status.code), message: body))
                          return self.ciamAuthrequest.eventLoop.makeFailedFuture(error)
                      }
                
                do {
                    let newToken = try JSONDecoder().decode(OAuthAccessToken.self, from: responseData)
                    self.ciamAuthrequest.currentToken = newToken
                    self.ciamAuthrequest.tokenCreatedTime = Date()
                    
                    return self.ciamAuthrequest.eventLoop.makeSucceededFuture(newToken)
                } catch {
                    return self.ciamAuthrequest.eventLoop.makeFailedFuture(error)
                }
            }
        } catch {
            return self.ciamAuthrequest.eventLoop.makeFailedFuture(error)
        }
    }
    
}
// MARK: 获取JWT公钥
extension CiamClient {
    
    public struct JWTPublicKey: Codable {
        public let keys: [PublicKey]
        
        public struct PublicKey: Codable {
            public let kty, e, kid, n: String
        }
    }
    
    public func getJWTPublicKey() -> EventLoopFuture<JWTPublicKey> {
        let getJWTUri = "\(self.config.userDomain)/oauth2/jwks"
        do {
            
            let request = try HTTPClient.Request(url: getJWTUri, method: .GET)
            
            return ciamAuthrequest.httpClient.execute(request: request, eventLoop: .delegate(on: ciamAuthrequest.eventLoop)).flatMap { response in
                
                guard var byteBuffer = response.body,
                      let responseData = byteBuffer.readData(length: byteBuffer.readableBytes),
                      response.status == .ok else {
                          let body = response.body?.getString(at: response.body?.readerIndex ?? 0, length: response.body?.readableBytes ?? 0) ?? ""
                          let error = CiamAuthError(error: CiamAuthAPIErrorBody(status: .unknownError, code: Int(response.status.code), message: body))
                          return self.ciamAuthrequest.eventLoop.makeFailedFuture(error)
                      }
                
                do {
                    let newModel = try JSONDecoder().decode(JWTPublicKey.self, from: responseData)
                    return self.ciamAuthrequest.eventLoop.makeSucceededFuture(newModel)
                } catch {
                    return self.ciamAuthrequest.eventLoop.makeFailedFuture(error)
                }
            }
        } catch {
            return self.ciamAuthrequest.eventLoop.makeFailedFuture(error)
        }
    }
}
// MARK: 刷新Token
extension CiamClient {
    public func ciamRefreshToken(_ refreshToken: String? = nil) -> EventLoopFuture<OAuthAccessToken> {
        self.ciamAuthrequest.refreshableToken.refresh(refreshToken)
    }
}
// MARK: 注销Token
extension CiamClient {
    public func revokeToken() -> EventLoopFuture<Void> {
        let revokeUri = "\(self.config.userDomain)/oauth2/revoke?client_id=\(self.credentials.clientId)&token=\(self.ciamAuthrequest.currentToken?.refresh_token ?? "")"
        do {
            
            let request = try HTTPClient.Request(url: revokeUri, method: .GET)
            
            return ciamAuthrequest.httpClient.execute(request: request, eventLoop: .delegate(on: ciamAuthrequest.eventLoop)).flatMap { response in
                
                guard var byteBuffer = response.body,
                      let responseData = byteBuffer.readData(length: byteBuffer.readableBytes),
                      let _ = String(data: responseData, encoding: .utf8),
                      response.status == .ok else {
                          let body = response.body?.getString(at: response.body?.readerIndex ?? 0, length: response.body?.readableBytes ?? 0) ?? ""
                          let error = CiamAuthError(error: CiamAuthAPIErrorBody(status: .unknownError, code: Int(response.status.code), message: body))
                          return self.ciamAuthrequest.eventLoop.makeFailedFuture(error)
                      }
                
                return self.ciamAuthrequest.eventLoop.makeSucceededFuture(())
            }
        } catch {
            return self.ciamAuthrequest.eventLoop.makeFailedFuture(error)
        }
    }
}
// MARK: 获取 OpenID Provider配置
extension CiamClient {
    
    public struct OpenIdProviderModel: Codable {
        public let issuer, authorizationEndpoint, tokenEndpoint: String
        public let tokenEndpointAuthMethodsSupported: [String]
        public let jwksURI: String
        public let responseTypesSupported, grantTypesSupported, subjectTypesSupported, idTokenSigningAlgValuesSupported: [String]
        public let scopesSupported: [String]

        enum CodingKeys: String, CodingKey {
            case issuer
            case authorizationEndpoint = "authorization_endpoint"
            case tokenEndpoint = "token_endpoint"
            case tokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported"
            case jwksURI = "jwks_uri"
            case responseTypesSupported = "response_types_supported"
            case grantTypesSupported = "grant_types_supported"
            case subjectTypesSupported = "subject_types_supported"
            case idTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported"
            case scopesSupported = "scopes_supported"
        }
    }
    
    public func getOpenIdProviderInfo() -> EventLoopFuture<OpenIdProviderModel> {
        let openIdProviderUri = "\(self.config.userDomain)/.well-known/openid-configuration"
        do {
            
            let request = try HTTPClient.Request(url: openIdProviderUri, method: .GET)
            
            return ciamAuthrequest.httpClient.execute(request: request, eventLoop: .delegate(on: ciamAuthrequest.eventLoop)).flatMap { response in
                
                guard var byteBuffer = response.body,
                      let responseData = byteBuffer.readData(length: byteBuffer.readableBytes),
                      response.status == .ok else {
                          let body = response.body?.getString(at: response.body?.readerIndex ?? 0, length: response.body?.readableBytes ?? 0) ?? ""
                          let error = CiamAuthError(error: CiamAuthAPIErrorBody(status: .unknownError, code: Int(response.status.code), message: body))
                          return self.ciamAuthrequest.eventLoop.makeFailedFuture(error)
                      }
                
                do {
                    let newModel = try JSONDecoder().decode(OpenIdProviderModel.self, from: responseData)
                    return self.ciamAuthrequest.eventLoop.makeSucceededFuture(newModel)
                } catch {
                    return self.ciamAuthrequest.eventLoop.makeFailedFuture(error)
                }
            }
        } catch {
            return self.ciamAuthrequest.eventLoop.makeFailedFuture(error)
        }
    }
}
// MARK: 自定义工具
extension CiamClient {
    /// PKCE code_challenge ，计算方法请参考 RFC 7636，或直接使用开发库来生成。
    private func generateCodeChallenge(codeVerifier: String) -> String {
        let digest = SHA256.hash(data: Data(codeVerifier.utf8))
        let digestBase64 = Data(digest).base64EncodedString()
        
        let code_challenge = digestBase64
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        
        return code_challenge
    }
}

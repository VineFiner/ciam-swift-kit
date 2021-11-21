//
//  File.swift
//  
//
//  Created by Finer  Vine on 2021/11/27.
//

import Foundation

public protocol CiamAuthAPI {
    /// 获取用户信息
    func getUser() async throws -> UserInfoModel
}

public final class CiamAuthenticationAPI: CiamAuthAPI {
    
    let endpoint: String
    let request: CiamRequest
    
    init(endpoint: String, request: CiamRequest) {
        self.endpoint = endpoint
        self.request = request
    }
    
    public func getUser() async throws -> UserInfoModel {
        let url = "\(endpoint)/userinfo"
        return try await request.send(method: .GET, path: url).get()
    }
}

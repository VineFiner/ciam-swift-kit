//
//  File.swift
//  
//
//  Created by Finer  Vine on 2021/11/21.
//

import Foundation
import NIOCore
import AsyncHTTPClient
import NIOHTTP1
import OAuthSwiftCore

class CiamRequest: APIRequest {
    
    let refreshableToken: OAuthRefreshable
    let httpClient: HTTPClient
    let responseDecoder: JSONDecoder = JSONDecoder()
    var currentToken: OAuthAccessToken?
    var tokenCreatedTime: Date?
    var eventLoop: EventLoop

    init(httpClient: HTTPClient, eventLoop: EventLoop, oauth: OAuthRefreshable) {
        self.refreshableToken = oauth
        self.httpClient = httpClient
        self.eventLoop = eventLoop
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        self.responseDecoder.dateDecodingStrategy = .formatted(dateFormatter)
    }
    
    public func send<ACM: AnyCodableModel>(method: HTTPMethod, headers: HTTPHeaders = [:], path: String, query: String = "", body: HTTPClient.Body = .data(Data())) -> EventLoopFuture<ACM> {
        return withToken { token in
            return self._send(method: method, headers: headers, path: path, query: query, body: body, accessToken: token.access_token).flatMap { response in
                do {
                    let model = try self.responseDecoder.decode(ACM.self, from: response)
                    return self.eventLoop.makeSucceededFuture(model)
                } catch {
                    return self.eventLoop.makeFailedFuture(error)
                }
            }
        }
    }
    
    private func _send(method: HTTPMethod, headers: HTTPHeaders, path: String, query: String, body: HTTPClient.Body, accessToken: String) -> EventLoopFuture<Data> {
        var _headers: HTTPHeaders = ["Authorization": "Bearer \(accessToken)",
                                     "Content-Type": "application/json"]
        headers.forEach { _headers.replaceOrAdd(name: $0.name, value: $0.value) }

        do {
            let request = try HTTPClient.Request(url: "\(path)?\(query)", method: method, headers: _headers, body: body)
            
            return httpClient.execute(request: request, eventLoop: .delegate(on: self.eventLoop)).flatMap { response in
                // If we get a 204 for example in the delete api call just return an empty body to decode.
                if response.status == .noContent {
                    return self.eventLoop.makeSucceededFuture("{}".data(using: .utf8)!)
                }

                guard var byteBuffer = response.body else {
                    fatalError("Response body from Ciam is missing! This should never happen.")
                }
                let responseData = byteBuffer.readData(length: byteBuffer.readableBytes)!

                guard (200...299).contains(response.status.code) else {
                    let error: Error
                    if let jsonError = try? self.responseDecoder.decode(CiamAuthError.self, from: responseData) {
                        error = jsonError
                    } else {
                        let body = response.body?.getString(at: response.body?.readerIndex ?? 0, length: response.body?.readableBytes ?? 0) ?? ""
                        error = CiamAuthError(error: CiamAuthAPIErrorBody(status: .unknownError, code: Int(response.status.code), message: body))
                    }
                    return self.eventLoop.makeFailedFuture(error)
                }
                return self.eventLoop.makeSucceededFuture(responseData)
            }
        } catch {
            return self.eventLoop.makeFailedFuture(error)
        }
    }
}

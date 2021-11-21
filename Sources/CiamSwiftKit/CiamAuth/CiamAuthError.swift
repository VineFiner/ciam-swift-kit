//
//  File.swift
//  
//
//  Created by Finer  Vine on 2021/11/28.
//

import Foundation
import OAuthSwiftCore

public struct CiamAuthError: OAuthSwiftCore.OAuthCustomError, OAuthSwiftCore.AnyCodableModel {
    public var error: CiamAuthAPIErrorBody
}

public struct CiamAuthAPIErrorBody: Codable {
    /// A container for the error details.
    public var status: Status
    /// An HTTP status code value, without the textual description.
    public var code: Int
    /// Description of the error. Same as `errors.message`.
    public var message: String
    
    public enum Status: String, RawRepresentable, Codable {
        case unknownError
        case alreadyExists = "ALREADY_EXISTS"
        case deadlineExceeded = "DEADLINE_EXCEEDED"
        case failedPrecondition = "FAILED_PRECONDITION"
        case internalError = "INTERNAL"
        case notFound = "NOT_FOUND"
        case permissionDenied = "PERMISSION_DENIED"
        case resourceExhausted = "RESOURCE_EXHAUSTED"
        case unauthenticated = "UNAUTHENTICATED"
        case unavailable = "UNAVAILABLE"
    }
}

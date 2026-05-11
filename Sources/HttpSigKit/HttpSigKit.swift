import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public enum HTTPSignatureError: Error, Equatable {
    case invalidURL(String)
    case missingRequiredComponent(String)
    case signingFailure(String)
}

public enum HTTPComponentIdentifier: String, Sendable, CaseIterable {
    case method = "@method"
    case authority = "@authority"
    case path = "@path"
    case query = "@query"
    case targetURI = "@target-uri"
    case contentDigest = "content-digest"
    case contentType = "content-type"
    case authorization = "authorization"
}

public struct HTTPSignatureRequest: Sendable {
    public let method: String
    public let url: URL
    public let headers: [String: String]

    public init(method: String, url: URL, headers: [String: String] = [:]) {
        self.method = method.uppercased()
        self.url = url
        self.headers = headers
    }
}

public struct HTTPSignatureResult: Sendable, Equatable {
    public let signatureInputHeaderValue: String
    public let signatureHeaderValue: String
    public let signingBase: String

    public init(signatureInputHeaderValue: String, signatureHeaderValue: String, signingBase: String) {
        self.signatureInputHeaderValue = signatureInputHeaderValue
        self.signatureHeaderValue = signatureHeaderValue
        self.signingBase = signingBase
    }
}

public struct HTTPMessageSigner: Sendable {
    public let label: String
    public let keyID: String
    public let algorithm: String
    public let coveredComponents: [HTTPComponentIdentifier]

    public init(
        label: String = "sig1",
        keyID: String,
        algorithm: String = "hmac-sha256",
        coveredComponents: [HTTPComponentIdentifier] = [.method, .authority, .path]
    ) {
        self.label = label
        self.keyID = keyID
        self.algorithm = algorithm
        self.coveredComponents = coveredComponents
    }

    public func sign(
        request: HTTPSignatureRequest,
        created: Int,
        expires: Int? = nil,
        nonce: String? = nil,
        signingFunction: (Data) throws -> Data
    ) throws -> HTTPSignatureResult {
        let signingBase = try buildSigningBase(request: request, coveredComponents: coveredComponents)
        let inputValue = buildSignatureInput(created: created, expires: expires, nonce: nonce)

        let inputData = Data(signingBase.utf8)
        let signatureBytes: Data
        do {
            signatureBytes = try signingFunction(inputData)
        } catch {
            throw HTTPSignatureError.signingFailure(String(describing: error))
        }

        let signatureHeader = "\(label)=:\(signatureBytes.base64EncodedString()):"
        return HTTPSignatureResult(
            signatureInputHeaderValue: inputValue,
            signatureHeaderValue: signatureHeader,
            signingBase: signingBase
        )
    }

    public func applyingSignatureHeaders(
        to request: URLRequest,
        created: Int,
        expires: Int? = nil,
        nonce: String? = nil,
        signingFunction: (Data) throws -> Data
    ) throws -> URLRequest {
        guard let url = request.url else {
            throw HTTPSignatureError.invalidURL("Request URL is missing")
        }
        let method = request.httpMethod ?? "GET"
        var headers: [String: String] = [:]
        request.allHTTPHeaderFields?.forEach { headers[$0.key.lowercased()] = $0.value }

        let signatureRequest = HTTPSignatureRequest(method: method, url: url, headers: headers)
        let signature = try sign(
            request: signatureRequest,
            created: created,
            expires: expires,
            nonce: nonce,
            signingFunction: signingFunction
        )

        var signedRequest = request
        signedRequest.setValue(signature.signatureInputHeaderValue, forHTTPHeaderField: "Signature-Input")
        signedRequest.setValue(signature.signatureHeaderValue, forHTTPHeaderField: "Signature")
        return signedRequest
    }

    private func buildSignatureInput(created: Int, expires: Int?, nonce: String?) -> String {
        let components = coveredComponents.map { "\"\($0.rawValue)\"" }.joined(separator: " ")
        var metadata = ["created=\(created)", "keyid=\"\(keyID)\"", "alg=\"\(algorithm)\""]
        if let expires {
            metadata.append("expires=\(expires)")
        }
        if let nonce, !nonce.isEmpty {
            metadata.append("nonce=\"\(nonce)\"")
        }
        return "\(label)=(\(components));\(metadata.joined(separator: ";"))"
    }

    private func buildSigningBase(
        request: HTTPSignatureRequest,
        coveredComponents: [HTTPComponentIdentifier]
    ) throws -> String {
        var lines: [String] = []
        for component in coveredComponents {
            let value = try resolve(component: component, request: request)
            lines.append("\"\(component.rawValue)\": \(value)")
        }
        return lines.joined(separator: "\n")
    }

    private func resolve(component: HTTPComponentIdentifier, request: HTTPSignatureRequest) throws -> String {
        switch component {
        case .method:
            return request.method.lowercased()
        case .authority:
            guard let host = request.url.host, !host.isEmpty else {
                throw HTTPSignatureError.missingRequiredComponent(component.rawValue)
            }
            if let port = request.url.port {
                return "\(host.lowercased()):\(port)"
            }
            return host.lowercased()
        case .path:
            let path = request.url.path
            return path.isEmpty ? "/" : path
        case .query:
            guard let query = request.url.query else {
                throw HTTPSignatureError.missingRequiredComponent(component.rawValue)
            }
            return "?\(query)"
        case .targetURI:
            var components = URLComponents(url: request.url, resolvingAgainstBaseURL: false)
            components?.fragment = nil
            if let absolute = components?.string {
                return absolute
            }
            throw HTTPSignatureError.invalidURL(request.url.absoluteString)
        case .contentDigest, .contentType, .authorization:
            if let value = request.headers[component.rawValue] {
                return value
            }
            if let value = request.headers[component.rawValue.lowercased()] {
                return value
            }
            throw HTTPSignatureError.missingRequiredComponent(component.rawValue)
        }
    }
}

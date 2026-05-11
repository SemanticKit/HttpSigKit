import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
@testable import HttpSigKit

@Test func signerBuildsDeterministicSigningBaseAndHeaders() throws {
    let signer = HTTPMessageSigner(
        keyID: "solid-key-1",
        coveredComponents: [.method, .authority, .path, .query, .contentDigest]
    )

    let request = HTTPSignatureRequest(
        method: "POST",
        url: try #require(URL(string: "https://pod.example/inbox/messages?limit=10")),
        headers: ["content-digest": "sha-256=:abc123=:"]
    )

    let result = try signer.sign(request: request, created: 1_707_000_000) { payload in
        Data(("sig:" + String(decoding: payload, as: UTF8.self)).utf8)
    }

    #expect(
        result.signingBase ==
            "\"@method\": post\n\"@authority\": pod.example\n\"@path\": /inbox/messages\n\"@query\": ?limit=10\n\"content-digest\": sha-256=:abc123=:"
    )
    #expect(
        result.signatureInputHeaderValue ==
            "sig1=(\"@method\" \"@authority\" \"@path\" \"@query\" \"content-digest\");created=1707000000;keyid=\"solid-key-1\";alg=\"hmac-sha256\""
    )
    #expect(result.signatureHeaderValue.hasPrefix("sig1=:") && result.signatureHeaderValue.hasSuffix(":"))
}

@Test func signerThrowsWhenRequiredHeaderIsMissing() throws {
    let signer = HTTPMessageSigner(
        keyID: "solid-key-1",
        coveredComponents: [.method, .contentDigest]
    )
    let request = HTTPSignatureRequest(
        method: "GET",
        url: try #require(URL(string: "https://pod.example/resource"))
    )

    #expect(throws: HTTPSignatureError.missingRequiredComponent("content-digest")) {
        _ = try signer.sign(request: request, created: 1_707_000_000) { _ in Data() }
    }
}

@Test func signerAppliesSignatureHeadersToURLRequest() throws {
    let signer = HTTPMessageSigner(
        keyID: "solid-key-1",
        coveredComponents: [.method, .authority, .path]
    )

    var request = URLRequest(url: try #require(URL(string: "https://pod.example/resource")))
    request.httpMethod = "GET"

    let signed = try signer.applyingSignatureHeaders(to: request, created: 1_707_000_000) { _ in
        Data("ok".utf8)
    }

    #expect(signed.value(forHTTPHeaderField: "Signature-Input")?.contains("keyid=\"solid-key-1\"") == true)
    #expect(signed.value(forHTTPHeaderField: "Signature") == "sig1=:b2s=:")
}

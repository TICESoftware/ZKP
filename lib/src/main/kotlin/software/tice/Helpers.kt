package software.tice

import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.util.*

fun decodeConcatSignature(base64UrlSignature: String): Pair<ByteArray, ByteArray> {
    val signatureByteArray = Base64URL.from(base64UrlSignature).decode()
    val dividerIndex = signatureByteArray.size/2
    val r = signatureByteArray.copyOfRange(0, dividerIndex)
    val s = signatureByteArray.copyOfRange(dividerIndex, signatureByteArray.size)
    return Pair(r,s)
}

fun encodeConcatSignature(r: ByteArray, s: ByteArray): String {
    require(r.size == s.size) // TODO: Add padding otherwise

    return Base64URL.encode(r+s).toString()
}

fun encodeECPublicKeyToPem(publicKey: ECPublicKey): String {
    val encoded = publicKey.encoded
    val base64Encoded = Base64.getEncoder().encodeToString(encoded)

    return """
        -----BEGIN PUBLIC KEY-----
        ${base64Encoded.chunked(64).joinToString("\n")}
        -----END PUBLIC KEY-----
    """.trimIndent()
}

fun encodeECPrivateKeyToPem(publicKey: ECPrivateKey): String {
    val encoded = publicKey.encoded
    val base64Encoded = Base64.getEncoder().encodeToString(encoded)

    return """
        -----BEGIN PRIVATE KEY-----
        ${base64Encoded.chunked(64).joinToString("\n")}
        -----END PRIVATE KEY-----
    """.trimIndent()
}
package software.tice

import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
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

fun encodeECPublicKeyToPem(ecKey: ECKey): String {
    val publicKey = ecKey.toECPublicKey()
    val encoded = publicKey.encoded
    val base64Encoded = Base64.getEncoder().encodeToString(encoded)

    return """
        -----BEGIN PUBLIC KEY-----
        ${base64Encoded.chunked(64).joinToString("\n")}
        -----END PUBLIC KEY-----
    """.trimIndent()
}
package software.tice

import com.nimbusds.jose.util.Base64URL

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

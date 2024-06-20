package software.tice

import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import java.math.BigInteger
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey

class ZKPProver(issuerPublicKey: ECPublicKey) {
    private val issuerPublicKeyECPoint: org.bouncycastle.math.ec.ECPoint
    private val secp256r1Spec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")

    init {
        issuerPublicKeyECPoint = secp256r1Spec.curve.createPoint(issuerPublicKey.w.affineX, issuerPublicKey.w.affineY)
    }

    fun createChallengeRequest(vpTokenFormat: VpTokenFormat, data: String): ChallengeRequestData {
        return when (vpTokenFormat) {
            VpTokenFormat.MSOMDOC -> error("not implemented yet")
            VpTokenFormat.SDJWT -> createChallengeRequestSdJwt(data)
        }
    }

    private fun createChallengeRequestSdJwt(jwt: String): ChallengeRequestData {
        val (digest, r) = parseSdJwt(jwt)
        return ChallengeRequestData(Base64URL.encode(digest).toString(), Base64URL.encode(r).toString())
    }

    fun answerChallenge(ephemeralPublicKey: ECKey, vpTokenFormat: VpTokenFormat, data: String): String {
        return when (vpTokenFormat) {
            VpTokenFormat.MSOMDOC -> error("not implemented yet")
            VpTokenFormat.SDJWT -> answerChallengeSdJwt(ephemeralPublicKey, data)
        }
    }

    private fun answerChallengeSdJwt(ephemeralPublicKey: ECKey, jwt: String): String {
        val (digest, r, s) = parseSdJwt(jwt)
        val (R, S) = answerChallenge(ephemeralPublicKey, digest, r, s)
        val signature = encodeConcatSignature(R, S)
        val parts = jwt.split(".")
        return "${parts[0]}.${parts[1]}.${signature}"
    }

    private fun answerChallenge(ephemeralPublicKey: ECKey, digest: ByteArray, signatureR: ByteArray, signatureS: ByteArray): Pair<ByteArray, ByteArray> {
        val s = BigInteger(1, signatureS)
        val sInv = s.modInverse(secp256r1Spec.curve.field.characteristic)

        val r = BigInteger(1, signatureR)
        val z = BigInteger(1, digest)
        val Gnew = secp256r1Spec.g.multiply(z).add(issuerPublicKeyECPoint.multiply(r))
        val R = Gnew.multiply(sInv).getEncoded(true)

        val ephemeralPublicKeyPoint = secp256r1Spec.curve.createPoint(ephemeralPublicKey.x.decodeToBigInteger(), ephemeralPublicKey.y.decodeToBigInteger())
        val S = ephemeralPublicKeyPoint.multiply(sInv).getEncoded(true)

        return Pair(R, S)
    }

    private data class ParsedSdJwt(val digest: ByteArray, val r: ByteArray, val s: ByteArray)
    private fun parseSdJwt(jwt: String): ParsedSdJwt {
        val parts = jwt.split(".")

        val md = MessageDigest.getInstance("SHA-256")
        md.update(Charsets.UTF_8.encode("${parts[0]}.${parts[1]}"))
        val digest = md.digest()

        val (r,s) = decodeConcatSignature(parts[2])
        return ParsedSdJwt(digest, r, s)
    }
}

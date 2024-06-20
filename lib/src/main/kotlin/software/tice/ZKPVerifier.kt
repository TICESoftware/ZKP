package software.tice

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.kotlincrypto.SecureRandom
import java.math.BigInteger
import java.security.interfaces.ECPublicKey
import java.util.concurrent.ConcurrentHashMap


class ZKPVerifier(issuerPublicKey: ECPublicKey) {
    private val issuerPublicKeyECPoint: org.bouncycastle.math.ec.ECPoint
    private val secp256r1Spec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
    private val challenges: ConcurrentHashMap<String, BigInteger> = ConcurrentHashMap()

    init {
        issuerPublicKeyECPoint = secp256r1Spec.curve.createPoint(issuerPublicKey.w.affineX, issuerPublicKey.w.affineY)
    }

    fun createChallenge(id: String, requestData: ChallengeRequestData): ECKey {
        val z = BigInteger(1, Base64URL.from(requestData.digest).decode())
        val r = BigInteger(1, Base64URL.from(requestData.r).decode())

        val Gnew = secp256r1Spec.g.multiply(z).add(issuerPublicKeyECPoint.multiply(r))

        val ephemeralPrivateKey = secp256r1Spec.curve.randomFieldElement(SecureRandom()).toBigInteger()
        challenges[id] = ephemeralPrivateKey

        val result = Gnew.multiply(ephemeralPrivateKey).normalize()
        val x = Base64URL.encode(result.affineXCoord.toBigInteger())
        val y = Base64URL.encode(result.affineYCoord.toBigInteger())

        return ECKey.Builder(Curve.P_256, x, y)
            .keyID(id)
            .build()
    }

    fun verifyChallenge(id: String, vpTokenFormat: VpTokenFormat, data: String): Boolean {
        return when (vpTokenFormat) {
            VpTokenFormat.MSOMDOC -> error("not implemented yet")
            VpTokenFormat.SDJWT -> verifyChallengeSdJwt(id, data)
        }
    }

    private fun verifyChallengeSdJwt(id: String, jwt: String): Boolean {
        check(challenges.containsKey(id))
        val (R,S) = decodeConcatSignature(jwt.split(".")[2])
        return verifyChallenge(id, R, S)
    }

    private fun verifyChallenge(id: String, R: ByteArray, S: ByteArray): Boolean {
        val ourS = secp256r1Spec.curve.decodePoint(R).multiply(challenges[id]).normalize()
        val theirS = secp256r1Spec.curve.decodePoint(S).normalize()
        return ourS == theirS
    }
}

//        val pubKeyPoint = ECPoint(result.affineXCoord.toBigInteger(), result.affineYCoord.toBigInteger())

//        val parameters = AlgorithmParameters.getInstance("EC")
//        parameters.init(ECGenParameterSpec("secp256r1"))
//        val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)
//        val pubSpec = ECPublicKeySpec(pubKeyPoint, ecParameters)
//        val kf = KeyFactory.getInstance("EC")
//        val key = kf.generatePublic(pubSpec) as ECPublicKey

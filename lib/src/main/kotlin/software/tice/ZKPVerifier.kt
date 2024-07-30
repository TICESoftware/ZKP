package software.tice

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.kotlincrypto.SecureRandom
import java.math.BigInteger
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.util.concurrent.ConcurrentHashMap


class ZKPVerifier(issuerPublicKey: ECPublicKey) {
    private val issuerPublicKeyECPoint: org.bouncycastle.math.ec.ECPoint
    private val secp256r1Spec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")

    init {
        issuerPublicKeyECPoint = secp256r1Spec.curve.createPoint(issuerPublicKey.w.affineX, issuerPublicKey.w.affineY)
    }

    /**
     * Creates a challenge for a transaction id based on a challenge request
     * @param requestData: Challenge request data from prover consisting of the digest of the payload and the `r` part of the signature
     * @return A public key that represents the challenge that is send to the prover and a secret key to verify the
     * challenge later (must be remembered and kept private)
     */
    fun createChallenge(requestData: ChallengeRequestData): Pair<ECPublicKey, ECPrivateKey> {
        val z = BigInteger(1, Base64URL.from(requestData.digest).decode())
        val r = BigInteger(1, Base64URL.from(requestData.r).decode())

        val Gnew = secp256r1Spec.g.multiply(z).add(issuerPublicKeyECPoint.multiply(r))

        val gen = ECKeyGenerator(Curve.P_256)
        val ephemeralPrivateKey = gen.generate().toECPrivateKey()
        val result = Gnew.multiply(ephemeralPrivateKey.s).normalize()

        val x = Base64URL.encode(result.affineXCoord.toBigInteger())
        val y = Base64URL.encode(result.affineYCoord.toBigInteger())

        return Pair(
            ECKey.Builder(Curve.P_256, x, y).build().toECPublicKey(),
            ephemeralPrivateKey
        )
    }

    fun verifyChallenge(vpTokenFormat: VpTokenFormat, data: String, key: ECPrivateKey): Boolean {
        return when (vpTokenFormat) {
            VpTokenFormat.MSOMDOC -> error("not implemented yet")
            VpTokenFormat.SDJWT -> verifyChallengeSdJwt(data, key)
        }
    }

    internal fun verifyChallengeSdJwt(jwt: String, key: ECPrivateKey): Boolean {
        val (R,S) = decodeConcatSignature(jwt.split(".")[2])
        return verifyChallenge(key, R, S)
    }

    internal fun verifyChallenge(key: ECPrivateKey, R: ByteArray, S: ByteArray): Boolean {
        val ourS = secp256r1Spec.curve.decodePoint(R).multiply(key.s).normalize()
        val theirS = secp256r1Spec.curve.decodePoint(S).normalize()
        return ourS == theirS
    }
}
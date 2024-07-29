package software.tice

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.util.Base64URL
import org.kotlincrypto.SecureRandom
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.*
import java.util.*
import kotlin.math.sign
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertFalse

val privateKeyPEM = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgb4UzEf6QFxSVF9yz
TA3+WFFacPJfp2iXgd+A2ZEzPJqhRANCAASwW742XU1e8LxEz8heJcu7wxUDtfuZ
dPcme9vm4fEr/klnGLTCrMZDXUqNm9QXwW1z+gYDNZ0+ZPAYSDlkPb3e
-----END PRIVATE KEY-----
"""

val publicKeyPEM = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsFu+Nl1NXvC8RM/IXiXLu8MVA7X7
mXT3Jnvb5uHxK/5JZxi0wqzGQ11KjZvUF8Ftc/oGAzWdPmTwGEg5ZD293g==
-----END PUBLIC KEY-----
"""

val ephPublicKeyPEM = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEy+m1V2j1LkiQqyksoDMhSBjFYgeV
OHxKsOSk1E+iudez3wFozx9tHArWhn8LcE7nqAcqoxr2v0NqMHb3noXvvQ==
-----END PUBLIC KEY-----
"""

class ZKPExampleTest {
    @Test fun runCorrectZKP() {
        // init keypair generator for issuer
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec("secp256r1"))
        val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)
        val ecKPGen = KeyPairGenerator.getInstance("EC")
        ecKPGen.initialize(ecParameters)

        // generate issuer keypair
        val issuerKP = ecKPGen.generateKeyPair()
        val issuerPublicKey = issuerKP.public as ECPublicKey

        // create random message and signed JWT
        val message = ByteArray(50)
        SecureRandom().nextBytesCopyTo(message)
        val signer = ECDSASigner(issuerKP.private, Curve.P_256)
        val jwtHeader = JWSHeader(JWSAlgorithm.ES256)
        val jwtSignature = signer.sign(jwtHeader, message)

        val JWT = "${jwtHeader.toBase64URL()}.${Base64URL.encode(message)}.${jwtSignature}"

        // verify
        val verifier = ZKPVerifier(issuerPublicKey)
        val prover = ZKPProver(issuerPublicKey)
        val transactionId = "random-id-string"

        val challengeRequestData = prover.createChallengeRequest(VpTokenFormat.SDJWT, JWT)
        val challenge = verifier.createChallenge(transactionId, challengeRequestData)
        val zkpJwt = prover.answerChallenge(challenge, VpTokenFormat.SDJWT, JWT)
        val proofed = verifier.verifyChallenge(transactionId, VpTokenFormat.SDJWT, zkpJwt)

        assertTrue { proofed }
    }

    @Test fun testAnswerChallenge() {
        val issuerPrivateKey = initializeECPrivateKeyFromPEM(privateKeyPEM)
        val issuerPublicKey = initializeECPublicKeyFromPEM(publicKeyPEM)
        val prover = ZKPProver(issuerPublicKey)

        val ephPubKey = initializeECPublicKeyFromPEM(ephPublicKeyPEM)
        val payload = "Some raw string"

        val md = MessageDigest.getInstance("SHA-256")
        md.update(Charsets.UTF_8.encode(payload))
        val digest = md.digest()
        println(Base64URL.encode(digest))

        val jwtHeader = JWSHeader(JWSAlgorithm.ES256)
        val signer = ECDSASigner(issuerPrivateKey, Curve.P_256)
        val signature = signer.sign(jwtHeader, digest)
        println(signature)

        val signatureString = signature.decodeToString()
        val (R, S) = decodeConcatSignature(signatureString)



//        prover.answerChallenge(com.nimbusds.jose.jwk.ECKey, digest, R, S)
    }

    @Test fun runUsingWrongPublicKey() {
        // init keypair generator for issuer
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec("secp256r1"))
        val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)
        val ecKPGen = KeyPairGenerator.getInstance("EC")
        ecKPGen.initialize(ecParameters)

        // generate issuer keypair
        val issuerKP = ecKPGen.generateKeyPair()
        val issuerPublicKey = issuerKP.public as ECPublicKey

        // DIFFERENT Public Key than Issuer
        val otherPublicKey = ecKPGen.generateKeyPair().public as ECPublicKey
        val prover = ZKPProver(otherPublicKey)

        // create random message and signed JWT
        val message = "Some message".encodeToByteArray()
        val signer = ECDSASigner(issuerKP.private, Curve.P_256)
        val jwtHeader = JWSHeader(JWSAlgorithm.ES256)
        val jwtSignature = signer.sign(jwtHeader, message)

        val JWT = "${jwtHeader.toBase64URL()}.${Base64URL.encode(message)}.${jwtSignature}"

        // verify
        val verifier = ZKPVerifier(issuerPublicKey)

        val transactionId = "random-id-string"

        val challengeRequestData = prover.createChallengeRequest(VpTokenFormat.SDJWT, JWT)
        val challenge = verifier.createChallenge(transactionId, challengeRequestData)
        val zkpJwt = prover.answerChallenge(challenge, VpTokenFormat.SDJWT, JWT)
        val proofed = verifier.verifyChallenge(transactionId, VpTokenFormat.SDJWT, zkpJwt)

        assertFalse { proofed }
    }

    fun initializeECPublicKeyFromPEM(pem: String): ECPublicKey {
        // Remove the first and last lines
        val pemCleaned = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("\\s".toRegex(), "")

        // Decode the base64 encoded string
        val decodedKey = Base64.getDecoder().decode(pemCleaned)

        // Convert to ECPrivateKey
        val keySpec = X509EncodedKeySpec(decodedKey)
        val keyFactory = KeyFactory.getInstance("EC")
        return keyFactory.generatePublic(keySpec) as ECPublicKey
    }

    fun initializeECPrivateKeyFromPEM(pem: String): ECPrivateKey {
        // Remove the first and last lines
        val pemCleaned = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("\\s".toRegex(), "")

        // Decode the base64 encoded string
        val decodedKey = Base64.getDecoder().decode(pemCleaned)

        // Convert to ECPrivateKey
        val keySpec = PKCS8EncodedKeySpec(decodedKey)
        val keyFactory = KeyFactory.getInstance("EC")
        return keyFactory.generatePrivate(keySpec) as ECPrivateKey
    }
}

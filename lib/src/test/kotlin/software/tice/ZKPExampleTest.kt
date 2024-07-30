package software.tice

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import org.kotlincrypto.SecureRandom
import java.io.StringReader
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
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
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1yu+OWNhRwFODLm/loVSpUdRZC2C
2aiB1+Et7Y300OsId7Mq9Z3ecplLGRaFAoPCkPylDysY0Hqp2VerlX7wgA==
-----END PUBLIC KEY-----
"""

val ephPrivateKeyPEM = """
-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBKcjFocoaViPkin2Tm
5XPAXPR5zYG7rA7px6i0CJ1ICA==
-----END PRIVATE KEY-----
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
        val message = "Some raw message".encodeToByteArray()
        val signer = ECDSASigner(issuerKP.private, Curve.P_256)
        val jwtHeader = JWSHeader(JWSAlgorithm.ES256)
        val jwtSignature = signer.sign(jwtHeader, message)

        val JWT = "${jwtHeader.toBase64URL()}.${Base64URL.encode(message)}.${jwtSignature}"
        println(JWT)
        // verify
        val verifier = ZKPVerifier(issuerPublicKey)
        val prover = ZKPProver(issuerPublicKey)
        val transactionId = "random-id-string"

        val challengeRequestData = prover.createChallengeRequest(VpTokenFormat.SDJWT, JWT)
        val (challenge, key) = verifier.createChallenge(challengeRequestData)
        val zkpJwt = prover.answerChallenge(challenge, VpTokenFormat.SDJWT, JWT)
        val proofed = verifier.verifyChallenge(VpTokenFormat.SDJWT, zkpJwt, key)

        assertTrue { proofed }
    }

    @Test fun testCreateChallenge() {
        val issuerKeyPair = ECKey.parseFromPEMEncodedObjects(publicKeyPEM + "\n" + privateKeyPEM).toECKey()
        val issuerPublicKey = issuerKeyPair.toECPublicKey()
        val verifier = ZKPVerifier(issuerPublicKey)

        val challengeRequestData = ChallengeRequestData("nLT2lz465dAnKWRSfjsImppvJ4gun1Rzy2_RPYH4fec", "Zh2GRwhm36gpV1TZc_j5E74P4taykE0CxKICGPxVP-Y")
        val (challengePubKey, challengePrivKey) = verifier.createChallenge(challengeRequestData)
        println(encodeECPublicKeyToPem(challengePubKey))
        println(encodeECPrivateKeyToPem(challengePrivKey))
    }

    @Test fun testAnswerChallengeFromSwift() {
        val issuerKeyPair = ECKey.parseFromPEMEncodedObjects(publicKeyPEM + "\n" + privateKeyPEM).toECKey()
        val issuerPublicKey = issuerKeyPair.toECPublicKey()
        val verifier = ZKPVerifier(issuerPublicKey)

        val jwtFromSwift = "eyJhbGciOiJFUzI1NiJ9.U29tZSByYXcgbWVzc2FnZQ.AjeYqOQOhFykHYcZaZ2Xa-M7CjM1XVXFYZ9pPXQBWdLvAhZoBLWgQeceUpGxRk9R92SRHkXPteF_ZJ_bFxEWvVCL"
        val key = BigInteger("51485709314959915694715422963369728803094646990902903965964523348002715876334")

//        val challengeKeyPair = ECKey.parseFromPEMEncodedObjects(ephPublicKeyPEM + "\n" + ephPrivateKeyPEM).toECKey()
//
////        assertTrue { keyS == key }
//        assertTrue {
//            verifier.verifyChallengeSdJwt(jwtFromSwift, key)
//        }
    }

    @Test fun testAnswerChallenge() {
        val issuerKeyPair = ECKey.parseFromPEMEncodedObjects(publicKeyPEM + "\n" + privateKeyPEM).toECKey()
        val issuerPrivateKey = issuerKeyPair.toECPrivateKey()
        val issuerPublicKey = issuerKeyPair.toECPublicKey()
        val prover = ZKPProver(issuerPublicKey)

        val ephPubKey = ECKey.parseFromPEMEncodedObjects(ephPublicKeyPEM).toECKey().toECPublicKey()
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
        val (signatureR, signatureS) = decodeConcatSignature(signatureString)

        val (newR, newS) = prover.answerChallenge(ephPubKey, digest, signatureR, signatureS)
        val encodedZKPSignature = encodeConcatSignature(newR, newS)
        println(encodedZKPSignature)
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
        val message = "Some raw message".encodeToByteArray()
        val signer = ECDSASigner(issuerKP.private, Curve.P_256)
        val jwtHeader = JWSHeader(JWSAlgorithm.ES256)
        val jwtSignature = signer.sign(jwtHeader, message)

        val JWT = "${jwtHeader.toBase64URL()}.${Base64URL.encode(message)}.${jwtSignature}"

        // verify
        val verifier = ZKPVerifier(issuerPublicKey)

        val transactionId = "random-id-string"

        val challengeRequestData = prover.createChallengeRequest(VpTokenFormat.SDJWT, JWT)
        val (challenge, key) = verifier.createChallenge(challengeRequestData)
        val zkpJwt = prover.answerChallenge(challenge, VpTokenFormat.SDJWT, JWT)
        val proofed = verifier.verifyChallenge(VpTokenFormat.SDJWT, zkpJwt, key)

        assertFalse { proofed }
    }
}

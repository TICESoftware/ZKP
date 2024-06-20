package software.tice

import java.security.interfaces.ECPublicKey

class ZKPExample {
    fun runZKP(issuerPublicKey: ECPublicKey, JWT: String) {
        val verifier = ZKPVerifier(issuerPublicKey)
        val prover = ZKPProver(issuerPublicKey)
        val transactionId = "random-id-string"

        val challengeRequestData = prover.createChallengeRequest(VpTokenFormat.SDJWT, JWT)

        val challenge = verifier.createChallenge(transactionId, challengeRequestData)

        val zkpJwt = prover.answerChallenge(challenge, VpTokenFormat.SDJWT, JWT)

        val proofed = verifier.verifyChallenge(transactionId, VpTokenFormat.SDJWT, zkpJwt)

        println("PROOFED? ${proofed}")
    }
}

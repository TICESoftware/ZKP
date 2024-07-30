package software.tice

import java.security.interfaces.ECPublicKey

class ZKPExample {
    fun runZKP(issuerPublicKey: ECPublicKey, JWT: String) {
        val verifier = ZKPVerifier(issuerPublicKey)
        val prover = ZKPProver(issuerPublicKey)

        val challengeRequestData = prover.createChallengeRequest(VpTokenFormat.SDJWT, JWT)

        val (challenge, key) = verifier.createChallenge(challengeRequestData)

        val zkpJwt = prover.answerChallenge(challenge, VpTokenFormat.SDJWT, JWT)

        val proofed = verifier.verifyChallenge(VpTokenFormat.SDJWT, zkpJwt, key)

        println("PROOFED? ${proofed}")
    }
}

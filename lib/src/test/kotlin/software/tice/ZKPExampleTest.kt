package software.tice

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.util.Base64URL
import org.kotlincrypto.SecureRandom
import java.security.AlgorithmParameters
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import kotlin.test.Test

class ZKPExampleTest {
    @Test fun runExample() {
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

        ZKPExample().runZKP(issuerPublicKey, JWT)
    }
}

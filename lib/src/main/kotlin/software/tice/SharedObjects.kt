package software.tice

enum class VpTokenFormat {
    SDJWT,
    MSOMDOC
}

data class ChallengeRequestData(val digest: String, val r: String)

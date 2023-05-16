package sortielab.library.fido2.fido.data_class


import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper

data class AuthenticationSignature(
    var credentialId: String = "",
    var rpid: String = "",
    var authenticatorData: String = "",
    var clientDataJson: String = "",
    var signature: String = ""
) {
    override fun toString(): String {
        return jacksonObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(this)
    }
}

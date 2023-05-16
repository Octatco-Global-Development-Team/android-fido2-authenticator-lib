package sortielab.library.fido2.fido.data_class


import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper

data class FIDO2AuthenticatePayload(
    var type: String = "",
    var id: String = "",
    var rawId: String = "",
    var response: WebAuthnAuthenticatePayloadResponse? = null
) {
    override fun toString(): String {
        return jacksonObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(this)
    }
}

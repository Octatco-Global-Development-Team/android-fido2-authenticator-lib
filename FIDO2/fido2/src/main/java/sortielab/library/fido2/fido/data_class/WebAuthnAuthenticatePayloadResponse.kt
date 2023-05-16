package sortielab.library.fido2.fido.data_class


import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper

data class WebAuthnAuthenticatePayloadResponse(
    var clientDataJSON: String,
    var authenticatorData: String,
    var signature: String,
    var userHandle: String,
) {
    override fun toString(): String {
        return jacksonObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(this)
    }
}
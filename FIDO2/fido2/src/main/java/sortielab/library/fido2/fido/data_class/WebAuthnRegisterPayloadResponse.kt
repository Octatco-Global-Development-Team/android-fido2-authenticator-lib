package sortielab.library.fido2.fido.data_class


import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper

data class WebAuthnRegisterPayloadResponse(
    var clientDataJSON: String,
    var attestationObject: String,
) {
    override fun toString(): String {
        return jacksonObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(this)
    }
}
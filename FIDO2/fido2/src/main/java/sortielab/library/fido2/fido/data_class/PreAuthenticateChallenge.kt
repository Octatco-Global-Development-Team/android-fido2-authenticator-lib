package sortielab.library.fido2.fido.data_class


import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper

data class PreAuthenticateChallenge(
    /***** The "rp" JSON sub-object *****/
    val rpId: String?,
    /***** Just one JSON attribute *****/
    val challenge: String?,
    /***** The "allowCredentials" JSON sub-object *****/
    val allowCredentials: ArrayList<CredentialData>?
) {
    override fun toString(): String {
        return jacksonObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(this)
    }

    fun validateData(): Boolean {
        return rpId != null && challenge != null && allowCredentials != null
    }
}

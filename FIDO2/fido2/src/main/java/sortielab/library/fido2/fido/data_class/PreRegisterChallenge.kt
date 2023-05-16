package sortielab.library.fido2.fido.data_class

import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper

data class PreRegisterChallenge(
    /***** The "rp" JSON sub-object *****/
    var rp: RPInfo?,

    /***** The "user" JSON sub-object *****/
    var user: UserInfo?,

    /***** Just two JSON attributes *****/
    var challenge: String?,
    var attestation: String?,

    /***** The "pubKeyCredParams" JSON sub-object *****/
    var pubKeyCredParams: ArrayList<CredentialData>?,
    var excludeCredentials: ArrayList<CredentialData>?,

    /***** The "authenticatorSelection" JSON sub-object *****/
    var authenticatorSelection: Any?,
) {
    constructor() : this(null, null, null, null, null, null, null)

    override fun toString(): String {
        return jacksonObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(this)
    }

    fun validateData(): Boolean {
        return rp != null && user != null && challenge != null && attestation != null
    }
}

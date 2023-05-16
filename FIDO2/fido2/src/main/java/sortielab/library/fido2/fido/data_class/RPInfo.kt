package sortielab.library.fido2.fido.data_class


import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper

data class RPInfo(
    var id: String?,
    var name: String?,
) {
    override fun toString(): String {
        return jacksonObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(this)
    }
}

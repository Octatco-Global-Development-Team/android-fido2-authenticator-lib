package sortielab.library.fido2.fido.excute

import com.google.gson.JsonObject
import sortielab.library.fido2.fido.data_class.FIDO2AuthenticatePayload
import sortielab.library.fido2.fido.data_class.FIDO2RegisterPayload

interface FIDO2ResponseCallback {

    /**
     * @param result Library Register Complete Return FIDO2RegisterPayload Object
     */
    fun onRegisterComplete(result: FIDO2RegisterPayload) {

    }

    /**
     * @param result Library Register Fail Return Json format string
     */
    fun onRegisterFail(result: String) {

    }

    /**
     * @param result Library Authenticate Complete Return FIDO2AuthenticatePayload Object
     */
    fun onAuthenticateComplete(result: FIDO2AuthenticatePayload) {

    }

    /**
     * @param result Library Authenticate Fail Return Json format string
     */
    fun onAuthenticateFail(result: String) {

    }
}
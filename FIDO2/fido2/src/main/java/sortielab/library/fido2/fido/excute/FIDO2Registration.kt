package sortielab.library.fido2.fido.excute

import android.os.Bundle
import android.os.Handler
import android.os.Message
import android.security.keystore.UserNotAuthenticatedException
import android.widget.Toast
import androidx.fragment.app.FragmentActivity
import com.google.gson.JsonObject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import sortielab.library.fido2.encrypt.crypto.AuthenticatorMakeCredential
import sortielab.library.fido2.encrypt.tools.CommonUtil
import sortielab.library.fido2.RootApplication
import sortielab.library.fido2.encrypt.tools.FidoConstants
import sortielab.library.fido2.fido.data_class.PreRegisterChallenge
import sortielab.library.fido2.fido.data_class.FIDO2RegisterPayload
import sortielab.library.fido2.fido.data_class.WebAuthnRegisterPayloadResponse
import sortielab.library.fido2.room.entity.PublicKeyCredential
import sortielab.library.fido2.room.repo.CredentialRepository

object FIDO2Registration {
    private lateinit var credRepository: CredentialRepository

    /**
     * @param handler Required Received Return Result
     * @param activity Required Activity Position This Use BioPrompt
     * @param preReg PreRegister Receive Server Response This Vale MUST NOT NULL inside Value
     * @param webOrigin The origin value requested for fido2 authentication is required.
     * @return Returns the PublicKey Credentials that were created. Returns null if an error occurs.
     */
    @Throws(UserNotAuthenticatedException::class)
    fun getPublicKey(
        handler: Handler,
        activity: FragmentActivity,
        preReg: PreRegisterChallenge,
        webOrigin: String
    ) {
        try {
            // STEP 1 Check Parameter
            require(preReg.rp != null && preReg.user != null && preReg.challenge != null && preReg.attestation != null) {
                "Parameter Must Not Required!!"
            }

            UserAuthenticate(activity, FidoConstants.USER_AUTHENTICATE_MODE_CREATE).apply {
                this.context = RootApplication.getInstance().baseContext
                this.bioCallback = object : BioCallback {
                    override fun onSuccess() {
                        makeFIDO2Key(handler, preReg, webOrigin)
                    }

                    override fun onFailed() {
                        Toast.makeText(activity.baseContext, "사용자 인증을 실패했습니다.", Toast.LENGTH_SHORT).show()
                    }
                }
                authenticate()
            }
        } catch (e: Exception) {
            sortielab.library.fido2.Dlog.w("Error: ${e::class.java.simpleName} ${e.message}")
            val key = FidoConstants.ERROR_EXCEPTION
            val msg = e.message ?: "Error Message Null"
            val ste = Thread.currentThread().stackTrace[4]
            val errJson = CommonUtil.getErrorJson(ste, key, msg)

            Message().apply {
                this.what = FidoConstants.FIDO_RESPONSE_CREATE_FAIL
                this.obj = Bundle().apply {
                    this.putString("error", errJson.toString())
                }
                handler.sendMessage(this)
            }
        }
    }

    private fun makeFIDO2Key(handler: Handler, preReg: PreRegisterChallenge, webOrigin: String) {
        credRepository = CredentialRepository(RootApplication.getInstance())
        try {
            val credObj = AuthenticatorMakeCredential.makeAuthenticatorCredential(preReg, webOrigin)
            sortielab.library.fido2.Dlog.i("CredObj: ${credObj ?: "Error!!"}")
            require(credObj != null) {
                "Device can not Make Credential"
            }
            when (credObj) {
                is PublicKeyCredential -> {
                    val payload = FIDO2RegisterPayload(
                        type = credObj.type,
                        id = credObj.credentialId,
                        rawId = credObj.userHandle,
                        response = WebAuthnRegisterPayloadResponse(
                            attestationObject = credObj.cborAttestation,
                            clientDataJSON = credObj.clientDataJson
                        )
                    )
                    CoroutineScope(Dispatchers.IO).launch {
                        kotlin.runCatching { credRepository.insert(credObj) }.onSuccess {
                            sortielab.library.fido2.Dlog.i("Key Stored: Id: $it")

                            Message().apply {
                                this.what = FidoConstants.FIDO_RESPONSE_CREATE_SUCCESS
                                this.obj = Bundle().apply {
                                    this.putString("origin", credObj.origin)
                                    this.putString(FidoConstants.BUNDLE_KEY_FIDO_PAYLOAD_DATA, payload.toString())
                                }
                                handler.sendMessage(this)
                            }
                        }
                    }
                }

                is JsonObject -> {
                    Message().apply {
                        this.what = FidoConstants.FIDO_RESPONSE_CREATE_FAIL
                        this.obj = Bundle().apply {
                            this.putString(FidoConstants.BUNDLE_KEY_ERROR, credObj.toString())
                        }
                        handler.sendMessage(this)
                    }
                }
            }
        } catch (e: Exception) {
            val key = FidoConstants.ERROR_EXCEPTION
            val msg = e.message ?: "Error Message Null"
            val ste = Thread.currentThread().stackTrace[4]
            val errJson = CommonUtil.getErrorJson(ste, key, msg)

            Message().apply {
                this.what = FidoConstants.FIDO_RESPONSE_CREATE_FAIL
                this.obj = Bundle().apply {
                    this.putString("error", errJson.toString())
                }
                handler.sendMessage(this)
            }
        }
    }
}
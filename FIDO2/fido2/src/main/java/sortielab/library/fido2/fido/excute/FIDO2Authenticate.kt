package sortielab.library.fido2.fido.excute

import android.os.Bundle
import android.os.Handler
import android.os.Message
import android.widget.Toast
import androidx.fragment.app.FragmentActivity
import com.google.gson.JsonObject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import sortielab.library.fido2.encrypt.crypto.AuthenticatorGetAssertion
import sortielab.library.fido2.encrypt.tools.CommonUtil
import sortielab.library.fido2.RootApplication
import sortielab.library.fido2.encrypt.tools.FidoConstants
import sortielab.library.fido2.fido.data_class.AuthenticationSignature
import sortielab.library.fido2.fido.data_class.FIDO2AuthenticatePayload
import sortielab.library.fido2.fido.data_class.PreAuthenticateChallenge
import sortielab.library.fido2.fido.data_class.WebAuthnAuthenticatePayloadResponse
import sortielab.library.fido2.room.entity.PublicKeyCredential
import sortielab.library.fido2.room.repo.CredentialRepository

object FIDO2Authenticate {
    private lateinit var credRepository: CredentialRepository

    /**
     * @param handler Required Received Return Result
     * @param activity Required Activity Position This Use BioPrompt
     * @param preAuth PreAuthenticate Receive Server Response This Vale MUST NOT NULL inside Value
     * @param webOrigin The origin value requested for fido2 authentication is required.
     * @return Returns the PublicKey Credentials that were created. Returns null if an error occurs.
     */
    fun getAuthenticateResponse(
        handler: Handler,
        activity: FragmentActivity,
        preAuth: PreAuthenticateChallenge,
        webOrigin: String
    ) {
        try {
            require(preAuth.rpId != null && preAuth.challenge != null && preAuth.allowCredentials != null) {
                "Parameter Must Not Required!!"
            }

            UserAuthenticate(activity, FidoConstants.USER_AUTHENTICATE_MODE_AUTHENTICATE).apply {
                this.context = RootApplication.getInstance().baseContext
                this.bioCallback = object : BioCallback {
                    override fun onSuccess() {
                        authenticateFIDO2Key(handler, preAuth, webOrigin)
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
                this.what = FidoConstants.FIDO_RESPONSE_AUTHENTICATE_FAIL
                this.obj = Bundle().apply {
                    this.putString(FidoConstants.BUNDLE_KEY_ERROR, errJson.toString())
                }
                handler.sendMessage(this)
            }
        }

    }

    private fun authenticateFIDO2Key(handler: Handler, preAuth: PreAuthenticateChallenge, webOrigin: String) {
        credRepository = CredentialRepository(RootApplication.getInstance())

        try {
            CoroutineScope(Dispatchers.IO).launch {
                var publicKeyCredential: PublicKeyCredential? = null
                for (allowCred in preAuth.allowCredentials!!) {
                    sortielab.library.fido2.Dlog.d("Find Id: $allowCred")
                    val pubKeyTemp = credRepository.getCredentialData(preAuth.rpId!!, allowCred.id!!)
                    sortielab.library.fido2.Dlog.v("Find Key: ${pubKeyTemp ?: "Not Found"}")
                    if (pubKeyTemp != null) {
                        sortielab.library.fido2.Dlog.v("Match Key: $pubKeyTemp")
                        publicKeyCredential = pubKeyTemp
                        break
                    }
                }
                require(publicKeyCredential != null) {
                    "PublicKeyCredential does not exist Please Register Key First"
                }

                // Get updated counter value
                publicKeyCredential.counter += FidoConstants.FIDO_COUNTER_ONE
                kotlin.runCatching { credRepository.update(publicKeyCredential) }.onSuccess {
                    try {
                        val authSignature = AuthenticatorGetAssertion.getAuthenticatorAssertion(
                            preAuth,
                            publicKeyCredential,
                            publicKeyCredential.counter,
                            webOrigin
                        )
                        sortielab.library.fido2.Dlog.i("AuthenticationSignature: ${authSignature ?: "Error!!"}")
                        require(authSignature != null) {
                            "Device can not Authenticate Signature"
                        }
                        when (authSignature) {
                            is AuthenticationSignature -> {
                                val payload = FIDO2AuthenticatePayload(
                                    type = publicKeyCredential.type,
                                    id = publicKeyCredential.credentialId,
                                    rawId = publicKeyCredential.userHandle,
                                    response = WebAuthnAuthenticatePayloadResponse(
                                        clientDataJSON = authSignature.clientDataJson,
                                        authenticatorData = authSignature.authenticatorData,
                                        signature = authSignature.signature,
                                        userHandle = "",
                                    )
                                )

                                Message().apply {
                                    this.what = FidoConstants.FIDO_RESPONSE_AUTHENTICATE_SUCCESS
                                    this.obj = Bundle().apply {
                                        this.putString("origin", publicKeyCredential.origin)
                                        this.putString(FidoConstants.BUNDLE_KEY_FIDO_PAYLOAD_DATA, payload.toString())
                                    }
                                    handler.sendMessage(this)
                                }
                            }

                            is JsonObject -> {
                                Message().apply {
                                    this.what = FidoConstants.FIDO_RESPONSE_AUTHENTICATE_FAIL
                                    this.obj = Bundle().apply {
                                        this.putString(FidoConstants.BUNDLE_KEY_ERROR, authSignature.toString())
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
                            this.what = FidoConstants.FIDO_RESPONSE_AUTHENTICATE_FAIL
                            this.obj = Bundle().apply {
                                this.putString(FidoConstants.BUNDLE_KEY_ERROR, errJson.toString())
                            }
                            handler.sendMessage(this)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            val key = FidoConstants.ERROR_EXCEPTION
            val msg = e.message ?: "Error Message Null"
            val ste = Thread.currentThread().stackTrace[4]
            val errJson = CommonUtil.getErrorJson(ste, key, msg)

            Message().apply {
                this.what = FidoConstants.FIDO_RESPONSE_AUTHENTICATE_FAIL
                this.obj = Bundle().apply {
                    this.putString(FidoConstants.BUNDLE_KEY_ERROR, errJson.toString())
                }
                handler.sendMessage(this)
            }
        }
    }
}
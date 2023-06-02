package sortielab.library.fido2.encrypt.crypto

import com.google.gson.JsonObject
import sortielab.library.fido2.Dlog
import sortielab.library.fido2.R
import sortielab.library.fido2.encrypt.tools.CommonUtil
import sortielab.library.fido2.RootApplication
import sortielab.library.fido2.encrypt.tools.FidoConstants
import sortielab.library.fido2.encrypt.data_class.FidoOperation
import sortielab.library.fido2.fido.data_class.AuthenticationSignature
import sortielab.library.fido2.fido.data_class.PreAuthenticateChallenge
import sortielab.library.fido2.room.entity.PublicKeyCredential
import java.nio.ByteBuffer

class AuthenticatorGetAssertion {
    companion object {
        /**
         * Signs an assertion on a challenge sent by the FIDO server.  Process is defined on W3C site
         * at: https://www.w3.org/TR/2019/REC-webauthn-1-20190304/#op-get-assertion
         *
         * @param preAuthData PreAuthenticateChallenge with necessary information
         * @param publicKeyCredential PublicKeyCredential object of the user
         * @param counter int value of the updated counter for the credential
         * @param webOrigin String containing the URL of the fully qualified domain name of the
         * site the app connects to. For example, if the app is communicating with
         * "https://demo.strongkey.com/mdba/rest/authenticateFidoKey" (the webserviceOrigin), this will
         * translate on the server to an RPID of "strongkey.com" (where the TLD is "com" and the +1
         * domain component is "strongkey").
         * @return JSONObject
         */
        fun getAuthenticatorAssertion(
            preAuthData: PreAuthenticateChallenge,
            publicKeyCredential: PublicKeyCredential,
            counter: Int,
            webOrigin: String
        ): Any? {
            // Get necessary values out of PreAuthenticateChallenge
            var rpid = preAuthData.rpId
            val challenge = preAuthData.challenge

            // Confirm that rpid is not null in the PreAuthentication challenge - we must use
            // RFC 6454 origin for RPID if FIDO server did not send an RPID
            if (rpid == null) {
                rpid = CommonUtil.getRfc6454Origin(webOrigin)
            }

            try {
                /**
                 * Step 1 - Create ClientData SHA256 Base64Url encoded string
                 * Data structure for CollectedClientData is as follows:
                 *  dictionary CollectedClientData {
                 *     required DOMString           type;       // Hard-coded to "public-key"
                 *     required DOMString           challenge;  // Sent by FIDO2 server
                 *     required DOMString           origin;     // Must be identical to rpid (verified by SACL)
                 *     TokenBinding                 tokenBinding; // Optional - empty for now
                 * };
                 */
                check(rpid != null && challenge != null)
                val rfc6454Origin = CommonUtil.getRfc6454Origin(webOrigin)
                val tldOrigin = CommonUtil.getTldPlusOne(webOrigin)
                if (!rpid.equals(tldOrigin, ignoreCase = true)) {
                    Dlog.w(
                        "${
                            RootApplication.getResource().getString(R.string.fido_info_authenticate_origin_rpid_mismatch)
                        } origin: $tldOrigin, rpid: $rpid"
                    )
                    return null
                }

                check(rfc6454Origin != null)
                // Origin and RPID match
                val clientDataJson =
                    CommonUtil.getBase64UrlSafeClientDataString(FidoOperation.GET, challenge, rfc6454Origin)
                val clientDataHash = CommonUtil.getBaseUrlSafeClientDataHash(FidoOperation.GET, challenge, rfc6454Origin)

                check(clientDataHash != null)
                Dlog.v("clientDataJson: $clientDataJson\nCalculated Base64UrlSafe ClientDataHash: $clientDataHash")

                /**
                 * Step 2 - Get the PublicKeyCredential for the user
                 */
                val credId = publicKeyCredential.credentialId
                Dlog.v("Using CredentialId: $credId")

                /**
                 * Step 3 - Create AuthenticationSignature object
                 */
                val authenticationSignature = AuthenticationSignature().apply {
                    this.rpid = rpid
                    this.credentialId = credId
                    this.clientDataJson = clientDataJson
                }
                Dlog.v(
                    "Built up authenticationSignature object: $authenticationSignature"
                )

                /**
                 * Step 4 - Generate Authenticator Data
                 * https://www.w3.org/TR/webauthn/#sec-authenticator-data
                 * The byte-array for authenticatorData has the following structure:
                 *
                 * 32-bytes with SHA256 digest of RPID
                 *  1-byte  with bit-flags providing information about UV, UP, etc.
                 *  4-bytes with a signature counter
                 *  N-bytes with extensions - variable length
                 *  N-bytes with clientDataHash
                 */
                val authenticationFlags =
                    CommonUtil.setFlags(FidoConstants.ANDROID_KEYSTORE_DEFAULT_AUTHENTICATION_FLAGS)
                val extensions = arrayListOf(FidoConstants.FIDO2_EXTENSION_USER_VERIFICATION_METHOD)
                val extensionResult = CommonUtil.getCborExtensions(extensions, publicKeyCredential.seModule)
                val byteBuff = ByteBuffer.allocate(37 + extensionResult.size)
                byteBuff.apply {
                    this.put(CommonUtil.getSha256(rpid)!!)
                    this.put(authenticationFlags)
                    this.put(CommonUtil.getCounterBytes(counter))
                    this.put(extensionResult)
                }
                val authenticatorDataBytes = byteBuff.array()
                authenticationSignature.authenticatorData = CommonUtil.urlEncode(authenticatorDataBytes)
                Dlog.v("Base64 URL-Encoded AuthenticatorData: ${authenticationSignature.authenticatorData}")

                /**
                 * Step 5 - Final step - Get a digital signature
                 * https://www.w3.org/TR/2019/REC-webauthn-1-20190304/#op-get-assertion
                 *
                 * Since we're only doing a FIDO authentication, the last parameter here -
                 * for a JCE Signature object will be NULL.
                 */
                val response = AndroidKeystoreDigitalSignature.makeAndroidDigitalSignature(authenticatorDataBytes, credId, clientDataHash, null)
                if(response != null) {
                    if(response is JsonObject) {
                        return response
                    } else {
                        authenticationSignature.signature = response.toString()
                    }
                    return authenticationSignature
                }
            } catch (e: Exception) {
                e.printStackTrace()
                val key = FidoConstants.ERROR_EXCEPTION
                val msg = e.message ?: "Error Message Null"
                val ste = Thread.currentThread().stackTrace[4]
                return CommonUtil.getErrorJson(ste, key, msg)
            }
            return null
        }
    }
}
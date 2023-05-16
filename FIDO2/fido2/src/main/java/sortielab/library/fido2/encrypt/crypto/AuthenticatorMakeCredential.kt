package sortielab.library.fido2.encrypt.crypto

import com.google.gson.JsonIOException
import com.google.gson.JsonObject
import com.google.gson.JsonParseException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex
import sortielab.library.fido2.R
import sortielab.library.fido2.encrypt.tools.CommonUtil
import sortielab.library.fido2.RootApplication
import sortielab.library.fido2.encrypt.tools.FidoConstants
import sortielab.library.fido2.encrypt.data_class.FidoOperation
import sortielab.library.fido2.fido.data_class.PreRegisterChallenge
import sortielab.library.fido2.room.entity.PublicKeyCredential
import java.io.IOException
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import java.util.Date

class AuthenticatorMakeCredential {
    companion object {
        /**
         * Returns a PublicKeyCredential object to the calling application - based on W3C standard at:
         * https://www.w3.org/TR/webauthn/#op-make-cred
         * Requirements for generating the new credential in the standard are as follows; all these
         * are encapsulated in the PreregisterChallenge object:
         *
         *      String clientDataHash,
         *      String rpid,
         *      String userid
         *      String displayName,
         *      boolean requireResidentKey,
         *      boolean requireUserPresence, (inverse of requireUserVerification)
         *      boolean requireUserVerification,
         *      JSONArray publicKeyCredentialParams,
         *      JSONArray excludeCredentials,
         *      Map extensions (if any)
         *
         * @param preReg PreRegisterChallenge with necessary information for keygen
         * @param webserviceOrigin String containing the URL of the fully qualified domain name of the
         * site the app connects to. For example, if the app is communicating with
         * "https://demo.strongkey.com/mdba/rest/authenticateFidoKey" (the webserviceOrigin), this will
         * translate on the server to an RPID of "strongkey.com" (where the TLD is "com" and the +1
         * domain component is "strongkey").
         * @return PublicKeyCredential object, if successful
         */
        fun makeAuthenticatorCredential(preReg: PreRegisterChallenge, webOrigin: String): Any? {
            // Get necessary values out of PreregisterChallenge
            val rpid = preReg.rp?.id
            val userid = preReg.user?.id
            val username = preReg.user?.name
            val dispName = preReg.user?.displayName
            val challenge = preReg.challenge

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
                check(rpid != null && userid != null && username != null && dispName != null && challenge != null)
                val rfc6454Origin = CommonUtil.getRfc6454Origin(webOrigin)
                val tldOrigin = CommonUtil.getTldPlusOne(webOrigin)
                if (!rpid.equals(tldOrigin, ignoreCase = true)) {
                    sortielab.library.fido2.Dlog.w(
                        "${
                            RootApplication.getResource().getString(R.string.fido_info_register_origin_rpid_mismatch)
                        } origin: $tldOrigin, rpid: $rpid"
                    )
                    return null
                }

                check(rfc6454Origin != null)
                val clientDataJson =
                    CommonUtil.getBase64UrlSafeClientDataString(FidoOperation.CREATE, challenge, rfc6454Origin)
                val clientDataHash = CommonUtil.getBaseUrlSafeClientDataHash(FidoOperation.CREATE, challenge, rfc6454Origin)

                check(clientDataHash != null)
                sortielab.library.fido2.Dlog.v("clientDataJson: $clientDataJson\nCalculated Base64UrlSafe ClientDataHash: $clientDataHash")

                /**
                 * Step 2 - Generate the public-private key-pair using ECDSA (mostly)
                 * https://developer.android.com/training/articles/keystore
                 * https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec
                 *
                 *  returns JSONObject newkey = new JSONObject()
                 *     .put(Constants.FIDO2_KEY_LABEL_KEYNAME, mKeyInfo.getKeystoreAlias())
                 *     .put(Constants.FIDO2_KEY_LABEL_ORIGIN, mKeyOrigin)
                 *     .put(Constants.FIDO2_KEY_LABEL_ALGORITHM, mAlgorithm)
                 *     .put(Constants.FIDO2_KEY_LABEL_SIZE, mKeyInfo.getKeySize())
                 *     .put(Constants.FIDO2_KEY_LABEL_USER_AUTH, mKeyInfo.isUserAuthenticationRequired())
                 *     .put(Constants.FIDO2_KEY_LABEL_SEMODULE, mSecureHardware)
                 *     .put(Constants.FIDO2_KEY_LABEL_HEX_PUBLIC_KEY, Hex.toHexString(mPublicKey.getEncoded()));
                 */
                // First generate the credential ID
                val credId = CommonUtil.getNewCredentialId(rpid, userid)
                sortielab.library.fido2.Dlog.v("Cred: $credId")
                val newKey = AndroidKeystoreKeyGeneration.makeAndroidKeystoreKey(credId, clientDataHash)
                if (newKey == null) {
                    sortielab.library.fido2.Dlog.w(RootApplication.getResource().getString(R.string.android_keystore_key_generate_failed))
                    return null
                } else {
                    if (newKey is JsonObject) {
                        if (newKey.has("error")) {
                            sortielab.library.fido2.Dlog.w("Key Generate Error Occurred: ${newKey.getAsJsonObject("error")}")
                            return newKey
                        }
                    }
                }

                // No keygen errors
                sortielab.library.fido2.Dlog.v("Generated Key-Pair: $newKey, ${newKey::class.java.simpleName}")
                val json = newKey as JsonObject
                // Key-pair generated - create PublicKeyCredential object for persistence to RoomDB
                val publicKeyCredential = PublicKeyCredential(
                    id = 0,
                    counter = FidoConstants.FIDO_COUNTER_ZERO,
                    rpid = rpid,
                    userid = userid,
                    username = username,
                    displayName = dispName,
                    credentialId = CommonUtil.urlEncode(credId),
                    clientDataJson = clientDataJson,
                    createDate = Date().time,
                    type = FidoConstants.JSON_KEY_PUBLIC_KEY_TYPE,
                    keySize = json.get(FidoConstants.FIDO2_KEY_LABEL_SIZE).asInt,
                    keyAlias = json.get(FidoConstants.FIDO2_KEY_LABEL_KEY_NAME).asString,
                    keyOrigin = json.get(FidoConstants.FIDO2_KEY_LABEL_ORIGIN).asString,
                    seModule = json.get(FidoConstants.FIDO2_KEY_LABEL_SE_MODULE).asString,
                    publicKey = json.get(FidoConstants.FIDO2_KEY_LABEL_HEX_PUBLIC_KEY).asString,
                    keyAlgorithm = json.get(FidoConstants.FIDO2_KEY_LABEL_ALGORITHM).asString,
                    userHandle = CommonUtil.urlEncode(json.toString().toByteArray(Charsets.UTF_8)),
                    origin = rfc6454Origin
                )
                sortielab.library.fido2.Dlog.v("Built up PublicKeyCredential: $publicKeyCredential")

                /**
                 * Step 3 - Create Attested Credential Data byte array
                 * https://www.w3.org/TR/webauthn/#attested-credential-data
                 * Array has to be CBOR map as follows:
                 *      aaguid:  16 bytes
                 *      credentialIdLength:  2 bytes with value: L
                 *      credentialId:  L bytes
                 *      credentialPublicKey:  Variable length - in CBOR, shown at link above
                 */
                val pubKeyBytes = Hex.decode(publicKeyCredential.publicKey)
                var cosePubKey = ByteArray(0)
                var pubKeyLen = 0
                val pubKeySpec = X509EncodedKeySpec(pubKeyBytes)
                try {
                    val pubKey =
                        KeyFactory.getInstance(FidoConstants.JSON_KEY_PUBLIC_KEY_ALG_EC_LABEL, BouncyCastleProvider())
                            .generatePublic(pubKeySpec)
                    cosePubKey = CommonUtil.coseEncodePublicKey(pubKey)
                    pubKeyLen = cosePubKey.size
                    sortielab.library.fido2.Dlog.v("COSE PublicKey Length: ${Hex.toHexString(cosePubKey)} [$pubKeyLen]")
                } catch (e: NoSuchAlgorithmException) {
                    e.printStackTrace()
                } catch (e: InvalidKeySpecException) {
                    e.printStackTrace()
                }

                // Create byte array for attestedCredentialData
                val credIdBytes = credId.toByteArray(Charsets.UTF_8)
                val cidblen = credIdBytes.size.toShort()
                val twoBytes = ByteBuffer.allocate(2)
                twoBytes.putShort(cidblen)
                sortielab.library.fido2.Dlog.v("Allocate ByteBuffer With Bytes: ${(16 + 2 + cidblen + pubKeyLen)}")
                val byteBuffStep3 = ByteBuffer.allocate(16 + 2 + cidblen + pubKeyLen).apply {
                    put(Hex.decode(FidoConstants.WEBAUTHN_SORTIELAB_ANDROID_FIDO2_AAGUID))
                    put(twoBytes.array())
                    put(credIdBytes)
                    put(cosePubKey)
                }
                val attestedCredData = byteBuffStep3.array()


                /**
                 * Step 4 - Generate Authenticator Data
                 * https://www.w3.org/TR/webauthn/#sec-authenticator-data
                 * The byte-array for authenticatorData has the following structure:
                 *
                 * 32-bytes with SHA256 digest of RPID
                 *  1-byte  with bit-flags providing information about UV, UP, etc.
                 *  4-bytes with a signature counter
                 *  L-bytes with attestedCredentialData - variable length
                 *  N-bytes with extensions - variable length
                 */
                val registrationFlags = CommonUtil.setFlags(FidoConstants.ANDROID_KEYSTORE_DEFAULT_REGISTRATION_FLAGS)
                val extensions = arrayListOf(FidoConstants.FIDO2_EXTENSION_USER_VERIFICATION_METHOD)
                val extensionOutput = CommonUtil.getCborExtensions(
                    extensions,
                    newKey.get(FidoConstants.FIDO2_KEY_LABEL_SE_MODULE).asString
                )
                val curCounter = publicKeyCredential.counter
                val byteBuffStep4 = ByteBuffer.allocate(37 + attestedCredData.size + extensionOutput.size).apply {
                    put(CommonUtil.getSha256(rpid)!!)
                    put(registrationFlags)
                    put(CommonUtil.getCounterBytes(curCounter + FidoConstants.FIDO_COUNTER_ONE))
                    put(attestedCredData)
                    put(extensionOutput)
                }
                val authenticatorDataBytes = byteBuffStep4.array()
                publicKeyCredential.counter = curCounter + FidoConstants.FIDO_COUNTER_ONE
                publicKeyCredential.authenticatorData = Hex.toHexString(authenticatorDataBytes)
                sortielab.library.fido2.Dlog.v("Hex-Encoded Authenticator Data: ${Hex.toHexString(authenticatorDataBytes)}")

                /**
                 * Step 5 - Final step - Get an AndroidKeystore Key attestation
                 * https://www.w3.org/TR/webauthn/#android-key-attestation
                 * Attestation JSON needs to be as follows - except for the signature (over the
                 * concatenation of authenticatorData and clientDataHash) we have the other values
                 * for this JSON in PublicKeyCredential:
                 * {
                 *   fmt: "android-key",
                 *   attStmt: {
                 *              alg: -7  // (for ECDSA, or -257 for RSA)
                 *              sig: bytes  // (in what format?)
                 *              x5c: [ credCert: bytes, * (caCert: bytes) ] // Array of certificate bytes
                 *           }
                 * }
                 */
                val response =
                    AndroidKeystoreAttestation.makeAndroidKeyAttestation(authenticatorDataBytes, credId, clientDataHash)
                if (response != null) {
                    val fidoAndKeyStoreAttestation =
                        response.getAsJsonObject(FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_FIDO)
                    publicKeyCredential.jsonAttestation =
                        fidoAndKeyStoreAttestation.getAsJsonObject(FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_FIDO_JSON_FORMAT).toString()
                    publicKeyCredential.cborAttestation =
                        fidoAndKeyStoreAttestation.get(FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_FIDO_CBOR_FORMAT).asString
                    return publicKeyCredential
                }
            } catch (e: Exception) {
                e.printStackTrace()
                when (e) {
                    is IOException,
                    is NoSuchAlgorithmException,
                    is JsonIOException,
                    is JsonParseException -> {
                        e.printStackTrace()
                        val key = FidoConstants.ERROR_EXCEPTION
                        val msg = e.message ?: "Error Message Null"
                        val ste = Thread.currentThread().stackTrace[4]
                        return CommonUtil.getErrorJson(ste, key, msg)
                    }
                }
            }
            return null
        }
    }
}
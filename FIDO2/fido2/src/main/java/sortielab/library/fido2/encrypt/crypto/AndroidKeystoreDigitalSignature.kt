package sortielab.library.fido2.encrypt.crypto

import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import com.google.gson.JsonIOException
import com.google.gson.JsonParseException
import org.bouncycastle.util.encoders.Hex
import sortielab.library.fido2.R
import sortielab.library.fido2.encrypt.tools.CommonUtil
import sortielab.library.fido2.RootApplication
import sortielab.library.fido2.encrypt.tools.FidoConstants
import sortielab.library.fido2.encrypt.data_class.KeyOrigin
import sortielab.library.fido2.encrypt.data_class.SecurityModule
import java.io.IOException
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.Signature
import java.security.UnrecoverableEntryException
import java.security.cert.CertificateException
import java.security.spec.InvalidKeySpecException

class AndroidKeystoreDigitalSignature {
    companion object {
        /**
         * Generates a FIDO digital signature over the concatenated authenticatorData and clientDataHash
         * using the private key of mCredentialId
         *
         * @param authenticatorDataBytes byte[] with calculated information for signing with PrivateKey
         * @param credId String containing the FIDO credential ID
         * @param clientDataHash String containing a Base64Url encoded SHA256 digest of components
         * that make up the CollectedClientData JSON object described in the WebAuthn spec at
         * (https://www.w3.org/TR/webauthn/#dictdef-collectedclientdata)
         *
         *  dictionary CollectedClientData {
         *     required DOMString           type;       // Hard-coded to "public-key"
         *     required DOMString           challenge;  // Sent by FIDO2 server
         *     required DOMString           origin;     // Must be identical to rpid (verified by SACL)
         *     TokenBinding                 tokenBinding; // Optional - empty for now
         * };
         *
         * @param signatureObj JCE Signature object, previously initialized by Android BiometricPrompt
         * for transaction authorization; or NULL for just FIDO authentication
         * @return Object Either a digital signature object or a JSONError
         */
        @Suppress("DEPRECATION")
        fun makeAndroidDigitalSignature(
            authenticatorDataBytes: ByteArray,
            credId: String,
            clientDataHash: String,
            signatureObj: Signature?
        ): Any? {
            val keyOrigin: KeyOrigin?
            val securityModule: SecurityModule? = null
            var privateKey: PrivateKey? = null
            var keyInfo: KeyInfo? = null

            // Retrieve newly generated key as part of attestation process
            try {
                // TODO: Check for local device authentication: PIN, Fingerprint, Face, etc.
                val keyStore = KeyStore.getInstance(FidoConstants.FIDO2_KEYSTORE_PROVIDER)
                keyStore.load(null)

                sortielab.library.fido2.Dlog.i("Credential Id: $credId, ${CommonUtil.urlDecode(credId).decodeToString()}")
                val keyEntry: KeyStore.Entry? = keyStore.getEntry(CommonUtil.urlDecode(credId).decodeToString(), null)
                if (keyEntry != null) {
                    if (keyEntry !is KeyStore.PrivateKeyEntry) {
                        val key = FidoConstants.ERROR_NOT_PRIVATE_KEY
                        val msg = RootApplication.getResource().getString(R.string.fido_err_not_private_key)
                        val ste = Thread.currentThread().stackTrace[4]
                        return CommonUtil.getErrorJson(ste, key, msg)
                    } else {
                        privateKey = keyEntry.privateKey
                        val factory =
                            KeyFactory.getInstance(privateKey.algorithm, FidoConstants.FIDO2_KEYSTORE_PROVIDER)
                        keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)
                    }
                }

                // Check the origin of the key - if Generated, it was generated inside AndroidKeystore
                // but not necessarily in hardware - emulators do support the AndroidKeystore in
                // software, so it can be misleading without attestation check
                check(keyInfo != null || privateKey != null)
                keyOrigin = when (keyInfo!!.origin) {
                    KeyProperties.ORIGIN_GENERATED -> {
                        KeyOrigin.GENERATED
                    }

                    KeyProperties.ORIGIN_IMPORTED -> {
                        KeyOrigin.IMPORTED
                    }

                    KeyProperties.ORIGIN_UNKNOWN -> {
                        KeyOrigin.UNKNOWN
                    }

                    else -> {
                        KeyOrigin.UNKNOWN
                    }
                }

                // print key information
                val algorithm = "${privateKey!!.algorithm} [${FidoConstants.FIDO2_KEY_ECDSA_CURVE}]"
                val secureHw = "${keyInfo.isInsideSecureHardware} [${securityModule ?: "null"}]"
                sortielab.library.fido2.Dlog.v(
                    "${
                        RootApplication.getResource().getString(R.string.fido_key_info_key_name)
                    } ${keyInfo.keystoreAlias}"
                )
                sortielab.library.fido2.Dlog.v("${RootApplication.getResource().getString(R.string.fido_key_info_origin)} $keyOrigin")
                sortielab.library.fido2.Dlog.v("${RootApplication.getResource().getString(R.string.fido_key_info_algorithm)} $algorithm")
                sortielab.library.fido2.Dlog.v("${RootApplication.getResource().getString(R.string.fido_key_info_size)} ${keyInfo.keySize}")
                sortielab.library.fido2.Dlog.v(
                    "${
                        RootApplication.getResource().getString(R.string.fido_key_info_user_auth)
                    } ${keyInfo.isUserAuthenticationRequired}"
                )
                sortielab.library.fido2.Dlog.v("${RootApplication.getResource().getString(R.string.fido_key_info_se_module)} $secureHw")

                // Initialize objects for digital signature
                val toBeSigned: ByteArray
                val base64URLSignature: String

                // Are we signing a business transaction or doing just FIDO authentication?
                if (signatureObj == null) {
                    // Doing FIDO authentication
                    // Initialize digital signature
                    val sign = Signature.getInstance(FidoConstants.FIDO2_SIGNATURE_ALGORITHM)
                    try {
                        sign.initSign((keyEntry as KeyStore.PrivateKeyEntry).privateKey)
                    } catch (e: UserNotAuthenticatedException) {
                        val key = FidoConstants.ERROR_UNAUTHENTICATED_USER
                        val msg = RootApplication.getResource().getString(R.string.fido_err_not_user_unauthenticated)
                        val ste = Thread.currentThread().stackTrace[4]
                        return CommonUtil.getErrorJson(ste, key, msg)
                    }

                    val clientDataHashBytes = CommonUtil.urlDecode(clientDataHash)
                    toBeSigned = ByteArray(authenticatorDataBytes.size + clientDataHashBytes.size)
                    System.arraycopy(authenticatorDataBytes, 0, toBeSigned, 0, authenticatorDataBytes.size)
                    System.arraycopy(
                        clientDataHashBytes, 0, toBeSigned, authenticatorDataBytes.size, clientDataHashBytes.size
                    )
                    sign.update(toBeSigned)
                    val digitalSignature = sign.sign()
                    base64URLSignature = CommonUtil.urlEncode(digitalSignature)
                } else {
                    // Signing a business transaction - but confirm by checking something in the object
                    if (signatureObj.algorithm.equals(FidoConstants.FIDO2_SIGNATURE_ALGORITHM, ignoreCase = true)) {
                        val clientDataHashBytes: ByteArray = CommonUtil.urlDecode(clientDataHash)
                        toBeSigned = ByteArray(authenticatorDataBytes.size + clientDataHashBytes.size)
                        System.arraycopy(authenticatorDataBytes, 0, toBeSigned, 0, authenticatorDataBytes.size)
                        System.arraycopy(
                            clientDataHashBytes, 0, toBeSigned, authenticatorDataBytes.size, clientDataHashBytes.size
                        )
                        signatureObj.update(toBeSigned)
                        val digitalSignature: ByteArray = signatureObj.sign()
                        base64URLSignature = CommonUtil.urlEncode(digitalSignature)
                    } else {
                        val key = FidoConstants.ERROR_SIGNATURE_OBJECT_NOT_INITIALIZED
                        val msg =
                            RootApplication.getResource().getString(R.string.fido_err_signature_object_not_initialized)
                        val ste = Thread.currentThread().stackTrace[4]
                        return CommonUtil.getErrorJson(ste, key, msg)
                    }
                }

                // Log and return the signature
                sortielab.library.fido2.Dlog.v(
                    "${RootApplication.getResource().getString(R.string.fido_key_info_tbs)} ${
                        Hex.toHexString(
                            toBeSigned
                        )
                    }\n${RootApplication.getResource().getString(R.string.fido_key_info_signature)} $base64URLSignature"
                )
                return base64URLSignature
            } catch (e: Exception) {
                e.printStackTrace()
                when (e) {
                    is KeyStoreException,
                    is CertificateException,
                    is IOException,
                    is NoSuchAlgorithmException,
                    is InvalidKeyException,
                    is NoSuchProviderException,
                    is InvalidKeySpecException,
                    is UnrecoverableEntryException,
                    is JsonIOException,
                    is JsonParseException -> {
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
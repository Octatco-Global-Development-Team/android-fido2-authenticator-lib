package sortielab.library.fido2.encrypt.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.google.gson.GsonBuilder
import com.google.gson.JsonIOException
import com.google.gson.JsonObject
import com.google.gson.JsonParseException
import org.bouncycastle.util.encoders.Hex
import sortielab.library.fido2.R
import sortielab.library.fido2.encrypt.tools.CommonUtil
import sortielab.library.fido2.RootApplication
import sortielab.library.fido2.encrypt.tools.FidoConstants
import sortielab.library.fido2.encrypt.data_class.KeyOrigin
import sortielab.library.fido2.encrypt.data_class.SecurityModule
import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.cert.CertificateException
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException

@Suppress("DEPRECATION")
class AndroidKeystoreKeyGeneration {
    companion object {
        /**
         * The code that tests the mobile device implementation for an SE or a TEE. Default values used
         * for key-generation constants are:
         *
         *      KEY_ALGORITHM_EC = ECDSA
         *      FIDO2_KEYSTORE_PROVIDER = AndroidKeystore
         *      PURPOSE_SIGN = Create a digital signature with the private key
         *      PURPOSE_VERIFY = Verify a digital signature with the public key
         *      FIDO2_KEY_ECDSA_CURVE = secp256r1, a NIST standard
         *      DIGEST_SHA256, _SHA384 and _SHA512 = Message digests for ECDSA signatures
         *      .setIsStrongBoxBacked(Boolean.TRUE) = Use a dedicated secure element - requires SDK 28 (Android P)
         *      .setUserAuthenticationRequired(Boolean.TRUE) = User must have device locked and require authentication to unlock
         *      FIDO2_USER_AUTHENTICATION_VALIDITY = 5 minutes
         *
         * If the hardware secure element is not available, the code will throw a StrongBoxUnavailableException,
         * upon which, the catch method will attempt to use the Trusted Execution Environment (TEE) to
         * generate the key-pair. Should usually work with TEE, but if there is no TEE, a key will be
         * generated anyway; the attestation validation will indicate if the key was generated in a
         * secure element, TEE or in software.
         *
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
         * @return JsonObject with the generated key's details, or error messages
         */
        fun makeAndroidKeystoreKey(credId: String, clientDataHash: String): Any? {
            val keyOrigin: KeyOrigin?
            var securityModule: SecurityModule? = null
            var keyPair: KeyPair? = null
            lateinit var keyGenerator: KeyPairGenerator

            // Generate key-pair in secure element, if available
            try {
                keyGenerator =
                    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, FidoConstants.FIDO2_KEYSTORE_PROVIDER)

                val timeout = FidoConstants.FIDO2_USER_AUTHENTICATION_VALIDITY * 60

                val keySpec =
                    KeyGenParameterSpec.Builder(credId, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                        .setAlgorithmParameterSpec(ECGenParameterSpec(FidoConstants.FIDO2_KEY_ECDSA_CURVE))
                        .setDigests(
                            KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA384,
                            KeyProperties.DIGEST_SHA512
                        )
                        .setAttestationChallenge(CommonUtil.urlDecode(clientDataHash))
                        .setIsStrongBoxBacked(true)
                        .setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    keySpec.setUserAuthenticationParameters(
                        timeout,
                        KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
                    )
                } else {
                    keySpec.setUserAuthenticationValidityDurationSeconds(timeout)
                }
                val keyBuilder = keySpec.build()
                keyGenerator.initialize(keyBuilder)
                keyPair = keyGenerator.generateKeyPair()
                securityModule = SecurityModule.SECURE_ELEMENT
                sortielab.library.fido2.Dlog.i(RootApplication.getResource().getString(R.string.fido_info_keygen_success_se))
            } catch (e: NoSuchMethodError) {
                sortielab.library.fido2.Dlog.w("${e::class.java.simpleName}: ${RootApplication.getResource().getString(R.string.fido_info_keygen_failure_se)}")
                try {
                    keyGenerator = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC,
                        FidoConstants.FIDO2_KEYSTORE_PROVIDER
                    )
                    val timeout = FidoConstants.FIDO2_USER_AUTHENTICATION_VALIDITY * 60

                    val keySpec =
                        KeyGenParameterSpec.Builder(credId, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                            .setAlgorithmParameterSpec(ECGenParameterSpec(FidoConstants.FIDO2_KEY_ECDSA_CURVE))
                            .setDigests(
                                KeyProperties.DIGEST_SHA256,
                                KeyProperties.DIGEST_SHA384,
                                KeyProperties.DIGEST_SHA512
                            )
                            .setAttestationChallenge(CommonUtil.urlDecode(clientDataHash))
                            .setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        keySpec.setUserAuthenticationParameters(
                            timeout,
                            KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
                        )
                    } else {
                        keySpec.setUserAuthenticationValidityDurationSeconds(timeout)
                    }
                    val keyBuilder = keySpec.build()
                    keyGenerator.initialize(keyBuilder)
                    keyPair = keyGenerator.generateKeyPair()
                    securityModule = SecurityModule.TRUSTED_EXECUTION_ENVIRONMENT
                    sortielab.library.fido2.Dlog.i(RootApplication.getResource().getString(R.string.fido_info_keygen_success_tee))
                } catch (e2: Exception) {
                    e2.printStackTrace()
                    when (e2) {
                        is NoSuchAlgorithmException,
                        is InvalidAlgorithmParameterException,
                        is NoSuchProviderException -> {
                            val key = FidoConstants.ERROR_EXCEPTION
                            val msg = e.message ?: "Error Message Null"
                            val ste = Thread.currentThread().stackTrace[4]
                            return CommonUtil.getErrorJson(ste, key, msg)
                        }
                    }
                }
            } catch (e: StrongBoxUnavailableException) {
                sortielab.library.fido2.Dlog.w("${e::class.java.simpleName}: ${RootApplication.getResource().getString(R.string.fido_info_keygen_failure_se)}")
                try {
                    keyGenerator = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC,
                        FidoConstants.FIDO2_KEYSTORE_PROVIDER
                    )
                    val timeout = FidoConstants.FIDO2_USER_AUTHENTICATION_VALIDITY * 60

                    val keySpec =
                        KeyGenParameterSpec.Builder(credId, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                            .setAlgorithmParameterSpec(ECGenParameterSpec(FidoConstants.FIDO2_KEY_ECDSA_CURVE))
                            .setDigests(
                                KeyProperties.DIGEST_SHA256,
                                KeyProperties.DIGEST_SHA384,
                                KeyProperties.DIGEST_SHA512
                            )
                            .setAttestationChallenge(CommonUtil.urlDecode(clientDataHash))
                            .setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        keySpec.setUserAuthenticationParameters(
                            timeout,
                            KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
                        )
                    } else {
                        keySpec.setUserAuthenticationValidityDurationSeconds(timeout)
                    }
                    val keyBuilder = keySpec.build()
                    keyGenerator.initialize(keyBuilder)
                    keyPair = keyGenerator.generateKeyPair()
                    securityModule = SecurityModule.TRUSTED_EXECUTION_ENVIRONMENT
                    sortielab.library.fido2.Dlog.i(RootApplication.getResource().getString(R.string.fido_info_keygen_success_tee))
                } catch (e2: Exception) {
                    e2.printStackTrace()
                    when (e2) {
                        is NoSuchAlgorithmException,
                        is InvalidAlgorithmParameterException,
                        is NoSuchProviderException -> {
                            val key = FidoConstants.ERROR_EXCEPTION
                            val msg = e.message ?: "Error Message Null"
                            val ste = Thread.currentThread().stackTrace[4]
                            return CommonUtil.getErrorJson(ste, key, msg)
                        }
                    }
                }
            } catch (e: Exception) {
                when (e) {
                    is IllegalStateException,
                    is InvalidAlgorithmParameterException,
                    is NoSuchAlgorithmException,
                    is NoSuchProviderException -> {
                        e.printStackTrace()
                        val key = FidoConstants.ERROR_EXCEPTION
                        val msg = e.message ?: "Error Message Null"
                        val ste = Thread.currentThread().stackTrace[4]
                        return CommonUtil.getErrorJson(ste, key, msg)
                    }
                }
            }

            // Retrieve newly generated key as part of attestation process
            try {
                // Get information on the key-pair
                val keyInfo: KeyInfo?

                // TODO: Check for local device authentication: PIN, Fingerprint, Face, etc.
                val keyStore = KeyStore.getInstance(FidoConstants.FIDO2_KEYSTORE_PROVIDER)
                keyStore.load(null)
                check(keyPair != null)

                val privateKey = keyPair.private
                val publicKey = keyPair.public
                val keyFactory = KeyFactory.getInstance(privateKey.algorithm, FidoConstants.FIDO2_KEYSTORE_PROVIDER)
                keyInfo = keyFactory.getKeySpec(privateKey, KeyInfo::class.java)
                sortielab.library.fido2.Dlog.v("ECDSA PublicKey Format: ${publicKey.format}")

                // Check the origin of the key - if Generated, it was generated inside AndroidKeystore
                // but not necessarily in hardware - emulators do support the AndroidKeystore in
                // software, so it can be misleading without attestation check
                check(keyInfo != null)
                keyOrigin = when (keyInfo.origin) {
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
                val algorithm = "${privateKey.algorithm} [${FidoConstants.FIDO2_KEY_ECDSA_CURVE}]"
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
                val gson = GsonBuilder().setPrettyPrinting().create()
                val keyJson = JsonObject().apply {
                    addProperty(FidoConstants.FIDO2_KEY_LABEL_KEY_NAME, keyInfo.keystoreAlias)
                    addProperty(FidoConstants.FIDO2_KEY_LABEL_ORIGIN, keyOrigin.name)
                    addProperty(FidoConstants.FIDO2_KEY_LABEL_ALGORITHM, algorithm)
                    addProperty(FidoConstants.FIDO2_KEY_LABEL_SIZE, keyInfo.keySize)
                    addProperty(FidoConstants.FIDO2_KEY_LABEL_USER_AUTH, keyInfo.isUserAuthenticationRequired)
                    addProperty(FidoConstants.FIDO2_KEY_LABEL_SE_MODULE, secureHw)
                    addProperty(FidoConstants.FIDO2_KEY_LABEL_HEX_PUBLIC_KEY, Hex.toHexString(publicKey.encoded))
                }
                sortielab.library.fido2.Dlog.v("Newly Generated FIDO2 Key: ${gson.toJson(keyJson)}")
                return keyJson
            } catch (e: Exception) {
                when (e) {
                    is KeyStoreException,
                    is CertificateException,
                    is IOException,
                    is NoSuchAlgorithmException,
                    is NoSuchProviderException,
                    is InvalidKeySpecException,
                    is JsonIOException,
                    is JsonParseException, -> {
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
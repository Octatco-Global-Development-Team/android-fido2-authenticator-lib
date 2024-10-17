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
import org.bouncycastle.jce.provider.BouncyCastleProvider
import sortielab.library.fido2.Dlog
import sortielab.library.fido2.R
import sortielab.library.fido2.RootApplication
import sortielab.library.fido2.encrypt.data_class.KeyOrigin
import sortielab.library.fido2.encrypt.data_class.SecurityModule
import sortielab.library.fido2.encrypt.tools.CommonUtil
import sortielab.library.fido2.encrypt.tools.FidoConstants
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
            var securityModule: SecurityModule? = null
            var keyPair: KeyPair? = null
            var attestationProvided: Boolean
            lateinit var keyGenerator: KeyPairGenerator

            Dlog.v("Starting key generation for credId: $credId")

            // Step 1: Try generating key-pair in Secure Element (StrongBox)
            try {
                Dlog.v("Attempting to generate key in Secure Element")
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
                        .setIsStrongBoxBacked(true)  // StrongBox backed
                        .setUserAuthenticationRequired(true)
                // Adjust for SDK versions
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    keySpec.setUserAuthenticationParameters(
                        timeout,
                        KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
                    )
                } else {
                    keySpec.setUserAuthenticationValidityDurationSeconds(timeout)
                }
                Dlog.v("KeySpec.. = ${keySpec}")
                keyGenerator.initialize(keySpec.build())
                Dlog.v("KeyGenerator.. = ${keyGenerator}")
                keyPair = keyGenerator.generateKeyPair()
                Dlog.v("KeyPair.. = ${keyPair}")
                securityModule = SecurityModule.SECURE_ELEMENT
                attestationProvided = true
                Dlog.i("Key generated successfully in Secure Element (StrongBox)")
            } catch (e: Exception) {
                Dlog.w("Secure Element (StrongBox) key generation failed, falling back to TEE: ${e.localizedMessage}")
                // Step 2: Fallback to TEE
                try {
                    keyPair = tryTEEKeyGeneration(credId, clientDataHash)
                    attestationProvided = true
                } catch (teeException: Exception) {
                    Dlog.e("TEE key generation failed, falling back to software-based key generation: ${teeException.localizedMessage}")
                    // Step 3: Fallback to software-based key generation
                    keyPair = generateWithoutAttestation(credId, clientDataHash)
                    attestationProvided = false
                }
                securityModule =
                    if (keyPair != null) SecurityModule.TRUSTED_EXECUTION_ENVIRONMENT else SecurityModule.SOFTWARE
            }

            // Step 4: Retrieve the newly generated key information
            if (keyPair != null) {
                Dlog.v("Attempting to retrieve key information")
                try {
                    return retrieveKeyInfo(keyPair, securityModule, clientDataHash, attestationProvided)
                } catch (e: Exception) {
                    Dlog.e("Exception during key retrieval: ${e.localizedMessage}")
                    return handleKeyGenerationError(e)
                }
            } else {
                Dlog.e("KeyPair generation failed")
                return null
            }
        }

        // Function to attempt key generation with TEE (without StrongBox)
        private fun tryTEEKeyGeneration(credId: String, clientDataHash: String): KeyPair? {
            Dlog.v("Attempting to generate key in TEE")
            val timeout = FidoConstants.FIDO2_USER_AUTHENTICATION_VALIDITY * 60
            val keyGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, FidoConstants.FIDO2_KEYSTORE_PROVIDER)

            val keySpec =
                KeyGenParameterSpec.Builder(credId, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec(FidoConstants.FIDO2_KEY_ECDSA_CURVE))
                    .setDigests(
                        KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512
                    )
                    .setAttestationChallenge(CommonUtil.urlDecode(clientDataHash))
                    .setUserAuthenticationRequired(true)  // TEE key generation without StrongBox

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                keySpec.setUserAuthenticationParameters(
                    timeout,
                    KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
                )
            } else {
                keySpec.setUserAuthenticationValidityDurationSeconds(timeout)
            }

            keyGenerator.initialize(keySpec.build())
            return keyGenerator.generateKeyPair()
        }

        // Function to fallback to software-based key generation (without hardware backing)
        private fun generateWithoutAttestation(credId: String, clientDataHash: String): KeyPair? {
            Dlog.v("Attempting to generate key wihtout attestation")
            val timeout = FidoConstants.FIDO2_USER_AUTHENTICATION_VALIDITY * 60
            val keyGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")

            val keySpec =
                KeyGenParameterSpec.Builder(credId, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec(FidoConstants.FIDO2_KEY_ECDSA_CURVE))
                    .setDigests(
                        KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512
                    )
                    .setUserAuthenticationValidityDurationSeconds(60)
                    .setUserAuthenticationRequired(true)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                keySpec.setUserAuthenticationParameters(
                    timeout,
                    KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
                )
            } else {
                keySpec.setUserAuthenticationValidityDurationSeconds(timeout)
            }

            keyGenerator.initialize(keySpec.build())
            return keyGenerator.generateKeyPair()
        }

        private fun retrieveKeyInfo(
            keyPair: KeyPair,
            securityModule: SecurityModule?,
            clientDataHash: String,
            attestationProvided: Boolean
        ): JsonObject {
            Dlog.v("Retrieving key information")

            val keyStore = KeyStore.getInstance(FidoConstants.FIDO2_KEYSTORE_PROVIDER)
            keyStore.load(null)

            val privateKey = keyPair.private
            val publicKey = keyPair.public
            val keyFactory = KeyFactory.getInstance(privateKey.algorithm, FidoConstants.FIDO2_KEYSTORE_PROVIDER)
            val keyInfo = keyFactory.getKeySpec(privateKey, KeyInfo::class.java)
            Dlog.v("Retrieved KeyInfo successfully")

            val keyOrigin = when (keyInfo.origin) {
                KeyProperties.ORIGIN_GENERATED -> KeyOrigin.GENERATED
                KeyProperties.ORIGIN_IMPORTED -> KeyOrigin.IMPORTED
                KeyProperties.ORIGIN_UNKNOWN -> KeyOrigin.UNKNOWN
                else -> KeyOrigin.UNKNOWN
            }

            val algorithm = "${privateKey.algorithm} [${FidoConstants.FIDO2_KEY_ECDSA_CURVE}]"
            val secureHw = "${keyInfo.isInsideSecureHardware} [${securityModule ?: "null"}]"
            Dlog.v("KeyInfo: Alias = ${keyInfo.keystoreAlias}, Origin = $keyOrigin, Algorithm = $algorithm")

            return JsonObject().apply {
                addProperty(FidoConstants.FIDO2_KEY_LABEL_KEY_NAME, keyInfo.keystoreAlias)
                addProperty(FidoConstants.FIDO2_KEY_LABEL_ORIGIN, keyOrigin.name)
                addProperty(FidoConstants.FIDO2_KEY_LABEL_ALGORITHM, algorithm)
                addProperty(FidoConstants.FIDO2_KEY_LABEL_SIZE, keyInfo.keySize)
                addProperty(FidoConstants.FIDO2_KEY_LABEL_USER_AUTH, keyInfo.isUserAuthenticationRequired)
                addProperty(FidoConstants.FIDO2_KEY_LABEL_SE_MODULE, secureHw)
                addProperty(FidoConstants.FIDO2_KEY_LABEL_HEX_PUBLIC_KEY, Hex.toHexString(publicKey.encoded))
                addProperty("AttestationProvided", attestationProvided)
            }
        }

        private fun handleKeyGenerationError(e: Exception): JsonObject {
            val key = FidoConstants.ERROR_EXCEPTION
            val msg = e.message ?: "Error Message Null"
            val ste = Thread.currentThread().stackTrace[4]
            return CommonUtil.getErrorJson(ste, key, msg)
        }
    }
}
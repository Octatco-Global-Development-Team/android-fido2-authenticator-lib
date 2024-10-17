package sortielab.library.fido2.encrypt.crypto

import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonIOException
import com.google.gson.JsonObject
import com.google.gson.JsonParseException
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import sortielab.library.fido2.Dlog
import sortielab.library.fido2.R
import sortielab.library.fido2.encrypt.cbor.CborEncoder
import sortielab.library.fido2.encrypt.tools.CommonUtil
import sortielab.library.fido2.RootApplication
import sortielab.library.fido2.encrypt.tools.FidoConstants
import sortielab.library.fido2.encrypt.data_class.KeyOrigin
import sortielab.library.fido2.encrypt.data_class.SecurityModule
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.StringWriter
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.Signature
import java.security.SignatureException
import java.security.UnrecoverableEntryException
import java.security.cert.Certificate
import java.security.cert.CertificateEncodingException
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.spec.InvalidKeySpecException

class AndroidKeystoreAttestation {
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
         *      FIDO2_USER_AUTHENTICATION_VALIDITY = 1 minutes
         *
         * If the hardware secure element is not available, the code will throw a StrongBoxUnavailableException,
         * upon which, the catch method will attempt to use the Trusted Execution Environment (TEE) to
         * generate the key-pair. Should usually work with TEE, but if there is no TEE, a key will be
         * generated anyway; the attestation validation will indicate if the key was generated in a
         * secure element, TEE or in software.
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
         * @return JSONObject with the attestation details from the app's server, or error messages
         */
        @Suppress("DEPRECATION")
        fun makeAndroidKeyAttestation(
            authenticatorDataBytes: ByteArray,
            credId: String,
            clientDataHash: String
        ): JsonObject? {
            val keyOrigin: KeyOrigin?
            val securityModule: SecurityModule? = null
            val certChain: ArrayList<Certificate>
            var privateKey: PrivateKey? = null
            var keyInfo: KeyInfo? = null

            try {
                val keyStore = KeyStore.getInstance(FidoConstants.FIDO2_KEYSTORE_PROVIDER)
                keyStore.load(null)

                Dlog.i("Credential Id: $credId")
                val keyEntry: KeyStore.Entry? = keyStore.getEntry(credId, null)
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
                Dlog.v(
                    "${
                        RootApplication.getResource().getString(R.string.fido_key_info_key_name)
                    } ${keyInfo.keystoreAlias}"
                )
                Dlog.v("${RootApplication.getResource().getString(R.string.fido_key_info_origin)} $keyOrigin")
                Dlog.v("${RootApplication.getResource().getString(R.string.fido_key_info_algorithm)} $algorithm")
                Dlog.v("${RootApplication.getResource().getString(R.string.fido_key_info_size)} ${keyInfo.keySize}")
                Dlog.v(
                    "${
                        RootApplication.getResource().getString(R.string.fido_key_info_user_auth)
                    } ${keyInfo.isUserAuthenticationRequired}"
                )
                Dlog.v("${RootApplication.getResource().getString(R.string.fido_key_info_se_module)} $secureHw")

                // Initialize Digital Signature
                val sign = Signature.getInstance(FidoConstants.FIDO2_SIGNATURE_ALGORITHM)
                try {
                    sign.initSign((keyEntry as KeyStore.PrivateKeyEntry).privateKey)
                } catch (e: UserNotAuthenticatedException) {
                    val key = FidoConstants.ERROR_UNAUTHENTICATED_USER
                    val msg = RootApplication.getResource().getString(R.string.fido_err_not_user_unauthenticated)
                    val ste = Thread.currentThread().stackTrace[4]
                    return CommonUtil.getErrorJson(ste, key, msg)
                }

                // Generate Signature
                val signature: ByteArray
                val base64URLSignature: String
                try {
                    val clientDataHashBytes = CommonUtil.urlDecode(clientDataHash)
                    val toBeSigned = ByteArray(authenticatorDataBytes.size + clientDataHashBytes.size)
                    System.arraycopy(authenticatorDataBytes, 0, toBeSigned, 0, authenticatorDataBytes.size)
                    System.arraycopy(
                        clientDataHashBytes, 0, toBeSigned, authenticatorDataBytes.size, clientDataHashBytes.size
                    )
                    sign.update(toBeSigned)
                    signature = sign.sign()
                    base64URLSignature = CommonUtil.urlEncode(signature)
                    Dlog.i(
                        "${RootApplication.getResource().getString(R.string.fido_key_info_tbs)} ${
                            Hex.toHexString(toBeSigned)
                        }\n${
                            RootApplication.getResource().getString(R.string.fido_key_info_signature)
                        } $base64URLSignature"
                    )
                } catch (e: SignatureException) {
                    e.printStackTrace()
                    val key = FidoConstants.ERROR_EXCEPTION
                    val msg = e.message ?: "Error Message Null"
                    val ste = Thread.currentThread().stackTrace[4]
                    return CommonUtil.getErrorJson(ste, key, msg)
                }

                // Get certificate chain of newly generated key
                val certChainData = keyEntry.certificateChain
                certChain = arrayListOf(*certChainData)
                val certsNumber = certChain.size
                if (certsNumber == 1) {
                    val key = FidoConstants.ERROR_SINGLE_CERTIFICATE_IN_CHAIN
                    val msg = RootApplication.getResource().getString(R.string.fido_err_single_certificate_in_chain)
                    val ste = Thread.currentThread().stackTrace[4]
                    return CommonUtil.getErrorJson(ste, key, msg)
                }
                Dlog.i(
                    "${
                        RootApplication.getResource().getString(R.string.fido_key_info_number_of_certificates)
                    } $certsNumber"
                )

                // Extract the certificate chain into a JsonObject for the server
                val jArray = JsonArray()
                for (i in 0 until certsNumber) {
                    val x509Cert = certChain[i] as X509Certificate
                    val sw = StringWriter()
                    val pw = PemWriter(sw)
                    val pemObject = PemObject("CERTIFICATE", x509Cert.encoded)
                    pw.writeObject(pemObject)
                    pw.close()
                    sw.close()
                    jArray.add(sw.toString())
                }

                // Create the JsonArray with the certificate chain - first the end-entity certificate
                val certArray = JsonArray()
                val firCert = JsonObject().apply {
                    this.addProperty(
                        FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_CREDENTIAL_CERTIFICATE,
                        jArray.get(0).asString
                    )
                }
                certArray.add(firCert)
                Dlog.i("Added Credential Certificate: #0")

                // Now the certificate chain in order
                for (i in 1 until certsNumber) {
                    val certObj = JsonObject().apply {
                        this.addProperty(
                            FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_CA_CERTIFICATE,
                            jArray.get(i).asString
                        )
                    }
                    Dlog.v("Added CA Certificate: #$i")
                    certArray.add(certObj)
                }
                Dlog.i("Number of JsonArray Certificate from JArray ${certArray.size()}")

                // This private method breaks down very long messages and prints it in sections
                val gson = GsonBuilder().setPrettyPrinting().create()
                CommonUtil.printVeryLongLogMessage("JsonArray Of X509 Certificate", gson.toJson(certArray))

                // Create the CBOR attestation for FIDO - sending Certificate chain rather than a
                // JSON array to save resources converting bytes to CBOR
                val cborAttestation =
                    buildCborAttestation(authenticatorDataBytes, privateKey.algorithm, signature, certChain, true)

                // Create Android Key Attestation with embedded digital signature
                val androidKeyAttestationObject = JsonObject().apply {
                    val rootJson = JsonObject().apply {
                        val fidoJson = JsonObject().apply {
                            val attStmtJson = JsonObject().apply {
                                this.addProperty(FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_ALGORITHM, -7)
                                this.addProperty(
                                    FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_SIGNATURE,
                                    base64URLSignature
                                )
                                this.add(
                                    FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_X509_CERTIFICATE_CHAIN,
                                    certArray
                                )
                            }
                            this.addProperty(
                                FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_FORMAT,
                                FidoConstants.ANDROID_KEYSTORE_ATTESTATION_VALUE_FORMAT
                            )
                            this.add(FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_STATEMENT, attStmtJson)
                        }
                        this.add(FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_FIDO_JSON_FORMAT, fidoJson)
                        this.addProperty(
                            FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_FIDO_CBOR_FORMAT,
                            cborAttestation
                        )
                    }
                    add(FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_FIDO, rootJson)
                }
                return androidKeyAttestationObject
            } catch (e: Exception) {
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

        /**
         * Converts information about the AndroidKeystore Attestation into a CBOR string
         * @param authenticatorData byte array containing "authData" - see for details
         * https://www.w3.org/TR/2019/REC-webauthn-1-20190304/#authenticator-data
         * @param algorithm String with algorithm type of the generated key-pair (usually EC, but
         * could be RSA too if the policy specified it - only 2 algorithms are supported by design)
         * @param signature byte array with digital signature of the concatenation of AuthenticatorData
         * and the message digest of CollectedClientData
         * @param certChain Certificate chain containing a chain with the end-entity certificate in
         * the first position and each issuer's certificate in subsequent positions, ending with the
         * self-signed Root CA certificate - all X509 data structures
         * @return String with Base64Url encoded CBOR output of the AndroidKeystore attestation - see
         * https://www.w3.org/TR/2019/REC-webauthn-1-20190304/#android-key-attestation. Result will
         * be something like this:
         *
         * {
         *     "authData": "0PhkNA1MKnPrdnd.....ac2bdIn",
         *     "fmt": "android-key",
         *     "attStmt": {
         *         "alg": -7, // for EC or -257 for RSA
         *         "sig": "MEYCIQD9...UuPdIc2ccInL0PhkNA1MKnPrdndszFGS",
         *         "x5c": [
         *                 "...", // credCert
         *                 "...", // caCert1  - issuer of credCert
         *                 "...", // caCert2  - issuer of caCert1
         *                 "..."  // rootCert - issuer of caCert2
         *         ]
         *     }
         * }
         *
         */
        @Throws(IOException::class, CertificateEncodingException::class, NoSuchAlgorithmException::class)
        fun buildCborAttestation(
            authenticatorData: ByteArray,
            algorithm: String?,
            signature: ByteArray?,
            certChain: ArrayList<Certificate>?,
            attestationProvided: Boolean
        ): String {
            val baos = ByteArrayOutputStream()
            val cbe = CborEncoder(baos)

            // Map entry with 3 elements of Key/Value
            cbe.writeMapStart(3)

            // First element - authenticator data - "authData"
            cbe.writeTextString(FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_AUTHENTICATOR_DATA)
            cbe.writeByteString(authenticatorData)

            // Second element - attestation format - "fmt"
            cbe.writeTextString(FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_FORMAT)
            cbe.writeTextString(
                if (attestationProvided)
                    FidoConstants.ANDROID_KEYSTORE_ATTESTATION_VALUE_FORMAT
                else
                    FidoConstants.ANDROID_KEYSTORE_ATTESTATION_NONE_VALUE_FORMAT
            )

            // Third element - attestation statement - "attStmt"
            cbe.writeTextString(FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_STATEMENT)
            if (!attestationProvided) {
                cbe.writeMapStart(0) // -> attStmt: {}
            } else {
                cbe.writeMapStart(3)

                // First sub-element of attStmt - only 2 choices
                if (algorithm != null) {
                    cbe.writeTextString(FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_ALGORITHM)
                    when (algorithm) {
                        FidoConstants.JSON_KEY_PUBLIC_KEY_ALG_EC_LABEL -> {
                            cbe.writeInt(FidoConstants.JSON_KEY_PUBLIC_KEY_ALG_ES256.toLong())
                        }

                        FidoConstants.JSON_KEY_PUBLIC_KEY_ALG_RSA_LABEL -> {
                            cbe.writeInt(FidoConstants.JSON_KEY_PUBLIC_KEY_ALG_RS256.toLong())
                        }

                        else -> {
                            throw NoSuchAlgorithmException("UnSupported Algorithm for AKS: $algorithm")
                        }
                    }
                } else {
                    throw NoSuchAlgorithmException("Empty algorithm parameter!!")
                }

                // Second sub-element of attStmt
                if (signature != null) {
                    cbe.writeTextString(FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_SIGNATURE)
                    cbe.writeByteString(signature)
                } else {
                    throw IOException("Empty Attestation Signature Parameter!!")
                }

                // Third sub-element of attStmt
                if (certChain != null) {
                    val chLen = certChain.size
                    cbe.writeTextString(FidoConstants.ANDROID_KEYSTORE_ATTESTATION_LABEL_X509_CERTIFICATE_CHAIN)
                    cbe.writeArrayStart(chLen)

                    // First sub-sub-element (of the Certificate chain)
                    var x509Cert = certChain[0] as X509Certificate
                    cbe.writeByteString(x509Cert.encoded)

                    // Remaining certificates in chain are all CA certificates
                    for (i in 1 until chLen) {
                        x509Cert = certChain[i] as X509Certificate
                        cbe.writeByteString(x509Cert.encoded)
                    }
                } else {
                    throw IOException("Empty Certificate Chain Parameter!!")
                }
            }

            // Convert to byte-array and hex-encode to a string for display
            val result = baos.toByteArray()
            val cborString = CommonUtil.urlEncode(result)
            Dlog.v("Cbor Attestation: $cborString")
            return cborString
        }
    }
}
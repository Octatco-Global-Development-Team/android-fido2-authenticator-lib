package sortielab.library.fido2.encrypt.tools

import android.net.Uri
import com.google.gson.JsonObject
import okhttp3.internal.publicsuffix.PublicSuffixDatabase
import org.bouncycastle.util.encoders.Hex
import sortielab.library.fido2.Dlog
import sortielab.library.fido2.encrypt.cbor.CborEncoder
import sortielab.library.fido2.encrypt.data_class.Encoding
import sortielab.library.fido2.encrypt.data_class.FidoOperation
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.UnsupportedEncodingException
import java.net.MalformedURLException
import java.net.URISyntaxException
import java.net.URL
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.util.Base64
import java.util.BitSet
import java.util.Date
import java.util.UUID
import kotlin.math.max
import kotlin.math.min

@Suppress("unused")
object CommonUtil {
    fun getErrorJson(ste: StackTraceElement, key: String, msg: String): JsonObject {
        val errClass = ste.fileName.replace(".java", "")
        val errMethod = ste.methodName

        val rootJson = JsonObject().apply {
            val infoJson = JsonObject().apply {
                addProperty("class", errClass)
                addProperty("method", errMethod)
                addProperty("key", key)
                addProperty("message", msg)
            }
            add("error", infoJson)
        }

        return rootJson
    }

    /**
     * Generates 4-byte counter from int
     */
    fun getCounterBytes(i: Int): ByteArray {
        val bb = ByteBuffer.allocate(4)
        bb.putInt(i)
        return bb.array()
    }

    /**
     * Base64 URL encoder
     */
    fun urlEncode(raw: String): String {
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(raw.toByteArray(StandardCharsets.UTF_8))
    }

    fun urlEncode(raw: ByteArray): String {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
    }

    /**
     * Base64 URL decoder
     */
    fun urlDecode(raw: String): ByteArray {
        return Base64.getUrlDecoder().decode(raw.toByteArray(StandardCharsets.UTF_8))
    }

    /**
     * Encodes an EC public key in the COSE/CBOR format - similar to:
     *
     * new CborEncoder(baos).encode(new CborBuilder()
     *      .addMap()
     *      .put(1, 2)  // kty: EC2 key type
     *      .put(3, -7) // alg: ES256 sig algorithm
     *      .put(-1, 1) // crv: P-256 curve
     *      .put(-2, x) // x-coord
     *      .put(-3, y) // y-coord
     *      .end()
     *      .build()
     *  );
     *
     * @param pubKey The public key.
     * @return byte[] A COSE_Key-encoded public key as byte array.
     */
    fun coseEncodePublicKey(pubKey: PublicKey): ByteArray {
        val ecPublicKey = pubKey as ECPublicKey
        val point = ecPublicKey.w

        val xVariableLen = point.affineX.toByteArray()
        val yVariableLen = point.affineY.toByteArray()

        // See Method Below
        val x = toUnsignedFixedLength(xVariableLen, 32)
        check(x.size == 32)
        val y = toUnsignedFixedLength(yVariableLen, 32)
        check(y.size == 32)

        val baos = ByteArrayOutputStream()
        try {
            val cbe = CborEncoder(baos)
            cbe.writeMapStart(5)

            cbe.writeInt(1)
            cbe.writeInt(2)

            cbe.writeInt(3)
            cbe.writeInt(-7)

            cbe.writeInt(-1)
            cbe.writeInt(1)

            cbe.writeInt(-2)
            cbe.writeByteString(x)

            cbe.writeInt(-3)
            cbe.writeByteString(y)
        } catch (e: IOException) {
            Dlog.w("Error: ${e.message}")
        }
        return baos.toByteArray()
    }

    /**
     * Generates a Base64-encoded SHA-256 digest of input
     * @param input byte[] with input to be hashed
     * @return ByteArray or Null
     */
    private fun getSha256(input: ByteArray): ByteArray? {
        return try {
            val md = MessageDigest.getInstance("SHA-256")
            md.digest(input)
        } catch (ex: NoSuchAlgorithmException) {
            Dlog.w("Error: ${ex.message}")
            null
        }
    }

    /**
     * Generates a Base64-encoded SHA-256 digest of input
     * @param input String with input to be hashed
     * @return ByteArray or Null
     */
    fun getSha256(input: String): ByteArray? {
        return try {
            val md = MessageDigest.getInstance("SHA-256")
            md.digest(input.toByteArray(Charsets.UTF_8))
        } catch (ex: NoSuchAlgorithmException) {
            Dlog.w("Error: ${ex.message}")
            null
        }
    }

    /**
     * Generates a Base64-encoded SHA-256 digest of input
     * @param input String with input to be hashed
     * @param encoding Constants.ENCODING indicating either BASE64 or HEX
     * @return String Base64- or Hex-encoded
     */
    fun getSha256(input: ByteArray, encoding: Encoding): String? {
        val digest: ByteArray = try {
            val md = MessageDigest.getInstance("SHA-256")
            md.digest(input)
        } catch (ex: NoSuchAlgorithmException) {
            Dlog.w("Error: ${ex.message}")
            return null
        }
        return if (encoding == Encoding.BASE64) {
            Base64.getEncoder().encodeToString(digest)
        } else {
            Hex.toHexString(digest)
        }
    }

    /**
     * Generates a Base64-encoded SHA-256 digest of input
     * @param input String with input to be hashed
     * @param encoding Constants.ENCODING indicating either BASE64 or HEX
     * @return String Base64- or Hex-encoded
     */
    fun getSha256(input: String, encoding: Encoding): String? {
        val digest: ByteArray = try {
            val md = MessageDigest.getInstance("SHA-256")
            md.digest(input.toByteArray(Charsets.UTF_8))
        } catch (ex: NoSuchAlgorithmException) {
            Dlog.w("Error: ${ex.message}")
            return null
        } catch (ex: UnsupportedEncodingException) {
            Dlog.w("Error: ${ex.message}")
            return null
        }
        return if (encoding == Encoding.BASE64) {
            Base64.getEncoder().encodeToString(digest)
        } else {
            Hex.toHexString(digest)
        }
    }


    /**
     * Print very long long message (> 4000 chars) because logcat won't print it
     * @param message JSONArray
     */
    fun printVeryLongLogMessage(msgtype: String, message: String) {
        val dashes = "\n---------------------------------------------------------------------\n"
        val msglen = message.length
        Dlog.i("Size of message: $msglen$dashes")
        val loop = msglen / 4000
        var startIndex = 0
        var endIndex = 4000
        for (i in 0 until loop) {
            Dlog.v("$msgtype - Part: $i\n${message.substring(startIndex, endIndex)}")
            startIndex = endIndex
            endIndex += 4000
        }
        Dlog.i(msgtype + " - Final Part: " + message.substring(startIndex) + dashes)
    }

    /**
     * Extract the TLD+1 from the origin of the app's webservice URL
     */
    fun getTldPlusOne(webURL: String): String? {
        val tld = PublicSuffixDatabase.get().getEffectiveTldPlusOne(webURL)
        return Uri.parse(tld).host ?: tld
    }

    /**
     * Extract the RFC6454 origin of the app's webservice URL
     * https://tools.ietf.org/html/rfc6454#page-10
     */
    fun getRfc6454Origin(webURL: String): String? {
        var origin: String? = null
        try {
            val url = URL(webURL)
//            val scheme = url.protocol
            val fqdn = url.host
            val port = url.port
            origin = if (port != -1) {
                val portStr = port.toString()
                val portPosition = webURL.indexOf(portStr)
                webURL.substring(0, (portPosition + (portStr.length)))
            } else {
                val fqdnPosition = webURL.indexOf(fqdn)
                webURL.substring(0, (fqdnPosition + fqdn.length))
            }
            Dlog.v("RFC6454-Origin: $origin\nURI: ${url.toURI()}")
        } catch (e: MalformedURLException) {
            e.printStackTrace()
        } catch (e: URISyntaxException) {
            e.printStackTrace()
        }
        return origin
    }

    /**
     * Create the JSON of CollectedClientData * https://www.w3.org/TR/webauthn/#collectedclientdata-hash-of-the-serialized-client-data * @param operation Constants.FIDO_OPERATION indicating if it is a WEBAUTHN CREATE or GET
     * @param challenge String Base64-encoded
     * @param origin String - Top Level Domain (TLD) + 1 - must match rpid
     * @return JSONObject containing the encoded JSON of CollectedClientData
     */
    private fun getClientDataJSON(operation: FidoOperation, challenge: String, origin: String): JsonObject {
        Dlog.v("Input Params - Operation: $operation\nChallenge: $challenge\nOrigin: $origin")

        // Assemble clientDataJson attributes into a JSON object
        var clientDataJson: JsonObject? = null
        when (operation) {
            FidoOperation.CREATE -> {
                clientDataJson = JsonObject().apply {
                    val token = JsonObject().apply {
                        addProperty(
                            FidoConstants.WEBAUTHN_CLIENT_DATA_TOKEN_BINDING_STATUS_KEY,
                            FidoConstants.WEBAUTHN_CLIENT_DATA_TOKEN_BINDING_STATUS_NOT_SUPPORTED
                        )
                    }
                    addProperty(
                        FidoConstants.WEBAUTHN_CLIENT_DATA_OPERATION_TYPE_KEY,
                        FidoConstants.WEBAUTHN_CLIENT_DATA_OPERATION_CREATE_VALUE
                    )
                    addProperty(FidoConstants.WEBAUTHN_CLIENT_DATA_CHALLENGE_KEY, challenge)
                    addProperty(FidoConstants.WEBAUTHN_CLIENT_DATA_ORIGIN_KEY, origin)
                    add(FidoConstants.WEBAUTHN_CLIENT_DATA_TOKEN_BINDING_KEY, token)
                }
            }

            FidoOperation.GET -> {
                clientDataJson = JsonObject().apply {
                    val token = JsonObject().apply {
                        addProperty(
                            FidoConstants.WEBAUTHN_CLIENT_DATA_TOKEN_BINDING_STATUS_KEY,
                            FidoConstants.WEBAUTHN_CLIENT_DATA_TOKEN_BINDING_STATUS_NOT_SUPPORTED
                        )
                    }
                    addProperty(
                        FidoConstants.WEBAUTHN_CLIENT_DATA_OPERATION_TYPE_KEY,
                        FidoConstants.WEBAUTHN_CLIENT_DATA_OPERATION_GET_VALUE
                    )
                    addProperty(FidoConstants.WEBAUTHN_CLIENT_DATA_CHALLENGE_KEY, challenge)
                    addProperty(FidoConstants.WEBAUTHN_CLIENT_DATA_ORIGIN_KEY, origin)
                    add(FidoConstants.WEBAUTHN_CLIENT_DATA_TOKEN_BINDING_KEY, token)
                }
            }
        }
        return clientDataJson
    }

    /**
     * Create a Base64Url encoded string of a JSON of ClientData * https://www.w3.org/TR/webauthn/#collectedclientdata-hash-of-the-serialized-client-data * @param operation Constants.FIDO_OPERATION indicating if it is a WEBAUTHN CREATE or GET
     * @param challenge String Base64-encoded
     * @param origin String - Top Level Domain (TLD) + 1 - must match rpid
     * @return String containing the Base64Url encoded JSON of CollectedClientData
     */
    fun getBase64UrlSafeClientDataString(operation: FidoOperation, challenge: String, origin: String): String {
        val clientDataJson = getClientDataJSON(operation, challenge, origin)
        Dlog.v("ClientDataJson: $clientDataJson")
        val utf8EncodedClientData = String(clientDataJson.toString().toByteArray(Charsets.UTF_8), Charsets.UTF_8)
        Dlog.v("Utf8EncodedClientData: $utf8EncodedClientData")
        val urlEncodedUTF8EncodedClientData = urlEncode(utf8EncodedClientData)
        Dlog.v("URLEncodedUTF8EncodedClientData: $urlEncodedUTF8EncodedClientData")
        return urlEncodedUTF8EncodedClientData
    }

    /**
     * Create a Base64Url encoded message digest (hash) of ClientData * https://www.w3.org/TR/webauthn/#collectedclientdata-hash-of-the-serialized-client-data * @param operation Constants.FIDO_OPERATION indicating if it is a WEBAUTHN CREATE or GET
     * @param challenge String Base64-encoded
     * @param origin String - Top Level Domain (TLD) + 1 - must match rpid
     * @return String containing the Base64Url encoded SHA256 hash of CollectedClientData or Null
     */
    fun getBaseUrlSafeClientDataHash(operation: FidoOperation, challenge: String, origin: String): String? {
        val base64UrlSafeEncodedClientDataString = getBase64UrlSafeClientDataString(operation, challenge, origin)
        Dlog.v("Base64UrlSafeEncodedClientDataString: $base64UrlSafeEncodedClientDataString")
        getSha256(urlDecode(base64UrlSafeEncodedClientDataString))?.let {
            val data = urlEncode(it)
            Dlog.v("UrlEncodedBase64UrlSafeEncodedClientDataHash: $data")
            return data
        }
        return null
    }

    /**
     * ECPoint coordinates are *unsigned* values that span the range [0, 2**32). The getAffine
     * methods return BigInteger objects, which are signed. toByteArray will output a byte array
     * containing the two's complement representation of the value, outputting only as many
     * bytes as necessary to do so. We want an unsigned byte array of length 32, but when we
     * call toByteArray, we could get:
     *
     * 1) A 33-byte array, if the point's unsigned representation has a high 1 bit.
     * "toByteArray" will prepend a zero byte to keep the value positive.
     * 2) A <32-byte array, if the point's unsigned representation has 9 or more high zero bits.
     *
     * Due to this, we need to either chop off the high zero byte or prepend zero bytes until
     * we have a 32-length byte array.
     */
    private fun toUnsignedFixedLength(arr: ByteArray, fixedLength: Int): ByteArray {
        val fixed = ByteArray(fixedLength)
        val offset = fixedLength - arr.size
        val srcPos = max(-offset, 0)
        val dstPos = max(offset, 0)
        val copyLength = min(arr.size, fixedLength)
        System.arraycopy(arr, srcPos, fixed, dstPos, copyLength)
        return fixed
    }


    /**
     * Sets bit-flags indicating what is asserted in Authenticator Data
     * https://www.w3.org/TR/webauthn/#sec-authenticator-data
     *
     * @param flagConfig: Boolean[] that holds UP, UV, AT, ED
     * @return flags: byte[] containing 1 byte.
     */
    fun setFlags(flagConfig: Array<Boolean>): ByteArray {
        // Sets the FLAGS, an 8-bit array, according to specifications
        val flagBits = BitSet(8)
        val userPresent = flagConfig[0]
        val userVerified = flagConfig[1]
        val hasAttested = flagConfig[2]
        val hasExtensions = flagConfig[3]

        flagBits[0] = userPresent // user present: 1 if true, 0 else
        flagBits[1] = false // RFU, default 0
        flagBits[2] = userVerified // user verified: 1 if true, 0 else
        flagBits[3] = false // RFU, default 0
        flagBits[4] = false // RFU, default 0
        flagBits[5] = false // RFU, default 0
        flagBits[6] = hasAttested // has attested credential data: 1 if true, 0 else
        flagBits[7] = hasExtensions // has extensions: 1 if true, 0 else

        /* Uses the helper method to convert BitSet to byte[]. */
        return bitSetToByteArray(flagBits)
    }

    /**
     * Helper method that converts a BitSet to byte[].
     *
     * @param bits The BitSet to be converted into a byte[] format.
     * @return bytes. The byte[] that represents @param bits.
     */
    private fun bitSetToByteArray(bits: BitSet): ByteArray {
        val bytes = ByteArray((bits.length() + 7) / 8)
        for (i in 0 until bits.length()) {
            if (bits[i]) {
                bytes[bytes.size - i / 8 - 1] = (bytes[bytes.size - i / 8 - 1].toInt() or (1 shl (i % 8))).toByte()
            }
        }
        return bytes
    }

    /**
     * Generate the CBOR for the UVM extension for AndroidKeystore
     * @param extensions A string array with required extensions from Constants
     * @throws IOException in case of I/O problems reading the CBOR-type from the underlying input stream.
     * @return byte[] CBOR output
     */
    @Throws(IOException::class)
    fun getCborExtensions(extensions: ArrayList<String>?, secureHw: String?): ByteArray {
        if (extensions == null || secureHw == null) {
            Dlog.w("Required Input Parameters are Not null")
            throw IOException("Required input parameters are null")
        }
        Dlog.v("ParamCheck: $extensions, $secureHw")

        val baos = ByteArrayOutputStream()
        val cbe = CborEncoder(baos)

        // How many extensions are we supporting? For now only UVM
        val extensionLen = extensions.size

        // What type of security hardware is in use?
        val seModule = secureHw.substring(0, 4)
        if (!(seModule.equals("true", ignoreCase = true))) {
            Dlog.w("Not using secure hardware - cannot use AndroidKeystore $${seModule}")
            throw IOException("Not using secure hardware - cannot use AndroidKeystore $${seModule}")
        }

        // Figure out key-protection: TEE or SE
        val stx = secureHw.indexOf('[')
        val etx = secureHw.indexOf(']')
        val keyProtection: Int
        val setType = secureHw.substring(stx + 1, etx)
        Dlog.v("Secure Hardware: $setType")
        keyProtection = if (setType.equals("SECURE_ELEMENT", ignoreCase = true)) {
            FidoConstants.FIDO_KEY_PROTECTION_HARDWARE + FidoConstants.FIDO_KEY_PROTECTION_SECURE_ELEMENT
        } else {
            FidoConstants.FIDO_KEY_PROTECTION_HARDWARE + FidoConstants.FIDO_KEY_PROTECTION_TEE
        }

        // Map entry with 1 elements for uvmEntry
        cbe.writeMapStart(extensionLen)

        for (i in 0 until extensionLen) {
            when (extensions[i]) {
                FidoConstants.FIDO2_EXTENSION_USER_VERIFICATION_METHOD -> {
                    // First element
                    cbe.writeTextString(FidoConstants.FIDO2_EXTENSION_USER_VERIFICATION_METHOD)

                    // Second element - CBOR Array of length 1
                    cbe.writeArrayStart(1)

                    // Item 1 - CBOR Array of length 3
                    cbe.writeArrayStart(3)

                    // Subitems of item 1
                    // See notes at end of file
                    cbe.writeInt(FidoConstants.FIDO_USER_VERIFY_PASSCODE.toLong())  // 0x00000004
                    cbe.writeInt(keyProtection.toLong())
                    cbe.writeInt(1)  // MATCHER_PROTECTION_SOFTWARE 0x0001
                }

                else -> {
                    Dlog.w("Not Other FIDO Extension Currently Supported Yet")
                    throw IOException("Not Other FIDO Extension Currently Supported Yet")
                }
            }
        }

        // Convert to byte-array and hex-encode to a string for display
        val result = baos.toByteArray()
        Dlog.v(String(Hex.encode(result), Charsets.UTF_8))
        return result
    }

    @Throws(UnsupportedEncodingException::class, NoSuchAlgorithmException::class)
    fun getNewCredentialId(rpid: String, userid: String): String {
        val uuid = UUID.randomUUID().toString()
        val nowTime = Date().time
        val byteBuff = ByteBuffer.allocate(8)

        val rpidBytes = rpid.toByteArray()
        val useridBytes = userid.toByteArray()
        val uuidBytes = uuid.toByteArray()
        val timeBytes = byteBuff.putLong(nowTime).array()

        var inputPos = 0
        val inputLen = rpidBytes.size + useridBytes.size + uuidBytes.size + timeBytes.size
        val input = ByteArray(inputLen)

        System.arraycopy(rpidBytes, 0, input, inputPos, rpidBytes.size)
        inputPos += rpidBytes.size

        System.arraycopy(useridBytes, 0, input, inputPos, useridBytes.size)
        inputPos += useridBytes.size

        System.arraycopy(uuidBytes, 0, input, inputPos, uuidBytes.size)
        inputPos += uuidBytes.size

        System.arraycopy(timeBytes, 0, input, inputPos, timeBytes.size)

        val digest = MessageDigest.getInstance("SHA-256")
        val output = digest.digest(input)

        val hexDigest = Hex.toHexString(output).uppercase()
        val sb = StringBuilder().apply {
            append(hexDigest.substring(0, 16))
            append("-")
            append(hexDigest.substring(16, 32))
            append("-")
            append(hexDigest.substring(32, 48))
            append("-")
            append(hexDigest.substring(48))
        }
        Dlog.v("Generated new Credential Id: $sb")
        return sb.toString()
    }
}
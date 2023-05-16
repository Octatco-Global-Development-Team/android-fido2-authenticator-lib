/**
 * JACOB - CBOR implementation in Kotlin.
 *
 * (C) Copyright - 2023 - K.H. Saebyeol <snorlax@sortielab.com>
 *
 * Licensed under Apache License v2.0.
 */
package sortielab.library.fido2.encrypt.cbor

import java.io.IOException
import java.io.OutputStream

/**
 * @param os the actual output stream to write the CBOR-encoded data to, cannot be <code>null</code>.
 */
@Suppress("unused")
class CborEncoder(private val os: OutputStream?) {
    private val outputStream: OutputStream

    companion object {
        private val NEG_INT_MASK = CborConstants.TYPE_NEGATIVE_INTEGER shl 5
    }

    /**
     * Creates a new {@link CborEncoder} instance.
     */
    init {
        if (os == null) {
            throw IllegalArgumentException("OutputStream cannot be null!!")
        }
        outputStream = os
    }

    /**
     * Interprets a given float-value as a half-precision float value and
     * converts it to its raw integer form, as defined in IEEE 754.
     * <p>
     * Taken from: <a href="http://stackoverflow.com/a/6162687/229140">this Stack Overflow answer</a>.
     * </p>
     *
     * @param fval the value to convert.
     * @return the raw integer representation of the given float value.
     */
    fun halfPrecisionToRawIntBits(fval: Float): Int {
        val fbits = java.lang.Float.floatToIntBits(fval)
        val sign = fbits ushr 16 and 0x8000
        var value = (fbits and 0x7fffffff) + 0x1000

        // might be or become NaN/Inf
        if (value >= 0x47800000) {
            return if (fbits and 0x7fffffff >= 0x47800000) { // is or must become NaN/Inf
                if (value < 0x7f800000) {
                    // was value but too large, make it +/-Inf
                    sign or 0x7c00
                } else sign or 0x7c00 or (fbits and 0x007fffff ushr 13)
                // keep NaN (and Inf) bits
            } else sign or 0x7bff
            // unrounded not quite Inf
        }
        if (value >= 0x38800000) {
            // remains normalized value
            return sign or (value - 0x38000000 ushr 13) // exp - 127 + 15
        }
        if (value < 0x33000000) {
            // too small for subnormal
            return sign // becomes +/-0
        }
        value = fbits and 0x7fffffff ushr 23
        // add subnormal bit, round depending on cut off and div by 2^(1-(exp-127+15)) and >> 13 | exp=0
        return sign or ((fbits and 0x7fffff or 0x800000) + (0x800000 ushr value - 102) ushr 126 - value)
    }

    /**
     * Writes the start of an indefinite-length array.
     *
     *
     * After calling this method, one is expected to write the given number of array elements, which can be of any type. No length checks are performed.<br></br>
     * After all array elements are written, one should write a single break value to end the array, see [.writeBreak].
     *
     *
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeArrayStart() {
        writeSimpleType(CborConstants.TYPE_ARRAY, CborConstants.BREAK)
    }

    /**
     * Writes the start of a definite-length array.
     *
     *
     * After calling this method, one is expected to write the given number of array elements, which can be of any type. No length checks are performed.
     *
     *
     * @param length the number of array elements to write, should &gt;= 0.
     * @throws IllegalArgumentException in case the given length was negative;
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeArrayStart(length: Int) {
        require(length >= 0) { "Invalid array-length!" }
        writeType(CborConstants.TYPE_ARRAY, length.toLong())
    }

    /**
     * Writes a boolean value in canonical CBOR format.
     *
     * @param value the boolean to write.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeBoolean(value: Boolean) {
        writeSimpleType(CborConstants.TYPE_FLOAT_SIMPLE, if (value) CborConstants.TRUE else CborConstants.FALSE)
    }

    /**
     * Writes a "break" stop-value in canonical CBOR format.
     *
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeBreak() {
        writeSimpleType(CborConstants.TYPE_FLOAT_SIMPLE, CborConstants.BREAK)
    }

    /**
     * Writes a byte string in canonical CBOR-format.
     *
     * @param bytes the byte string to write, can be `null` in which case a byte-string of length <tt>0</tt> is written.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeByteString(bytes: ByteArray?) {
        writeString(CborConstants.TYPE_BYTE_STRING, bytes)
    }

    /**
     * Writes the start of an indefinite-length byte string.
     *
     *
     * After calling this method, one is expected to write the given number of string parts. No length checks are performed.<br></br>
     * After all string parts are written, one should write a single break value to end the string, see [.writeBreak].
     *
     *
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeByteStringStart() {
        writeSimpleType(CborConstants.TYPE_BYTE_STRING, CborConstants.BREAK)
    }

    /**
     * Writes a double-precision float value in canonical CBOR format.
     *
     * @param value the value to write, values from [Double.MIN_VALUE] to [Double.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeDouble(value: Double) {
        writeUInt64(CborConstants.TYPE_FLOAT_SIMPLE shl 5, java.lang.Double.doubleToRawLongBits(value))
    }

    /**
     * Writes a single-precision float value in canonical CBOR format.
     *
     * @param value the value to write, values from [Float.MIN_VALUE] to [Float.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeFloat(value: Float) {
        writeUInt32(CborConstants.TYPE_FLOAT_SIMPLE shl 5, java.lang.Float.floatToRawIntBits(value))
    }

    /**
     * Writes a half-precision float value in canonical CBOR format.
     *
     * @param value the value to write, values from [Float.MIN_VALUE] to [Float.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeHalfPrecisionFloat(value: Float) {
        writeUInt16(CborConstants.TYPE_FLOAT_SIMPLE shl 5, halfPrecisionToRawIntBits(value))
    }

    /**
     * Writes a signed or unsigned integer value in canonical CBOR format, that is, tries to encode it in a little bytes as possible..
     *
     * @param value the value to write, values from [Long.MIN_VALUE] to [Long.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeInt(value: Long) {
        // extends the sign over all bits...
        val sign = value shr 63
        // in case value is negative, this bit should be set...
        val mt = (sign and NEG_INT_MASK.toLong()).toInt()
        // complement negative value...
        val calValue = sign xor value

        writeUInt(mt, calValue)
    }

    /**
     * Writes a signed or unsigned 16-bit integer value in CBOR format.
     *
     * @param value the value to write, values from <tt>[-65536..65535]</tt> are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeInt16(value: Int) {
        // extends the sign over all bits...
        val sign = value shr 31
        // in case value is negative, this bit should be set...
        // complement negative value...
        writeUInt16((sign and NEG_INT_MASK), (sign xor value) and 0xffff)
    }

    /**
     * Writes a signed or unsigned 32-bit integer value in CBOR format.
     *
     * @param value the value to write, values in the range <tt>[-4294967296..4294967295]</tt> are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeInt32(value: Long) {
        // extends the sign over all bits...
        val sign = value shr 63
        // in case value is negative, this bit should be set...
        val mt = (sign and NEG_INT_MASK.toLong()).toInt()
        // complement negative value...
        writeUInt32(mt, ((sign xor value) and 0xffffffffL).toInt())
    }

    /**
     * Writes a signed or unsigned 64-bit integer value in CBOR format.
     *
     * @param value the value to write, values from [Long.MIN_VALUE] to [Long.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeInt64(value: Long) {
        // extends the sign over all bits...
        val sign = value shr 63
        // in case value is negative, this bit should be set...
        val mt = (sign and NEG_INT_MASK.toLong()).toInt()
        // complement negative value...
        writeUInt64(mt, sign xor value)
    }

    /**
     * Writes a signed or unsigned 8-bit integer value in CBOR format.
     *
     * @param value the value to write, values in the range <tt>[-256..255]</tt> are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeInt8(value: Int) {
        // extends the sign over all bits...
        val sign = value shr 31
        // in case value is negative, this bit should be set...
        // complement negative value...
        writeUInt8((sign and NEG_INT_MASK), (sign xor value) and 0xff)
    }

    /**
     * Writes the start of an indefinite-length map.
     *
     *
     * After calling this method, one is expected to write any number of map entries, as separate key and value. Keys and values can both be of any type. No length checks are performed.<br></br>
     * After all map entries are written, one should write a single break value to end the map, see [.writeBreak].
     *
     *
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeMapStart() {
        writeSimpleType(CborConstants.TYPE_MAP, CborConstants.BREAK)
    }

    /**
     * Writes the start of a finite-length map.
     *
     *
     * After calling this method, one is expected to write any number of map entries, as separate key and value. Keys and values can both be of any type. No length checks are performed.
     *
     *
     * @param length the number of map entries to write, should &gt;= 0.
     * @throws IllegalArgumentException in case the given length was negative;
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeMapStart(length: Int) {
        if(length < 0) {
            throw IllegalArgumentException("Invalid length of map!")
        }
        writeType(CborConstants.TYPE_MAP, length.toLong())
    }

    /**
     * Writes a `null` value in canonical CBOR format.
     *
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeNull() {
        writeSimpleType(CborConstants.TYPE_FLOAT_SIMPLE, CborConstants.NULL)
    }

    /**
     * Writes a simple value, i.e., an "atom" or "constant" value in canonical CBOR format.
     *
     * @param simpleValue the (unsigned byte) value to write, values from <tt>32</tt> to <tt>255</tt> are supported (though not enforced).
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeSimpleValue(simpleValue: Byte) {
        // convert to unsigned value...
        val value = simpleValue.toInt() and 0xff
        writeType(CborConstants.TYPE_FLOAT_SIMPLE, value.toLong())
    }

    /**
     * Writes a signed or unsigned small (&lt;= 23) integer value in CBOR format.
     *
     * @param value the value to write, values in the range <tt>[-24..23]</tt> are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeSmallInt(value: Int) {
        // extends the sign over all bits...
        val sign = value shr 31
        val mt = (sign and NEG_INT_MASK)
        // in case value is negative, this bit should be set...
        // complement negative value...
//        val calValue = Math.min(0x17, sign xor value)
        outputStream.write((mt or value))
    }

    /**
     * Writes a semantic tag in canonical CBOR format.
     *
     * @param tag the tag to write, should &gt;= 0.
     * @throws IllegalArgumentException in case the given tag was negative;
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeTag(tag: Long) {
        if(tag < 0) {
            throw IllegalArgumentException("Invalid tag specification, cannot be negative!")
        }
        writeType(CborConstants.TYPE_TAG, tag)
    }

    /**
     * Writes an UTF-8 string in canonical CBOR-format.
     *
     *
     * Note that this method is *platform* specific, as the given string value will be encoded in a byte array
     * using the *platform* encoding! This means that the encoding must be standardized and known.
     *
     *
     * @param value the UTF-8 string to write, can be `null` in which case an UTF-8 string of length <tt>0</tt> is written.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeTextString(value: String?) {
        val str = value?.toByteArray(Charsets.UTF_8)
        writeString(CborConstants.TYPE_TEXT_STRING, str)
    }

    /**
     * Writes the start of an indefinite-length UTF-8 string.
     *
     *
     * After calling this method, one is expected to write the given number of string parts. No length checks are performed.<br></br>
     * After all string parts are written, one should write a single break value to end the string, see [.writeBreak].
     *
     *
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeTextStringStart() {
        writeSimpleType(CborConstants.TYPE_TEXT_STRING, CborConstants.BREAK)
    }

    /**
     * Writes an "undefined" value in canonical CBOR format.
     *
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    fun writeUndefined() {
        writeSimpleType(CborConstants.TYPE_FLOAT_SIMPLE, CborConstants.UNDEFINED)
    }

    /**
     * Encodes and writes the major type and value as a simple type.
     *
     * @param majorType the major type of the value to write, denotes what semantics the written value has;
     * @param value the value to write, values from [0..31] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    private fun writeSimpleType(majorType: Int, value: Int) {
        outputStream.write((majorType shl 5) or (value and 0x1f))
    }

    /**
     * Writes a byte string in canonical CBOR-format.
     *
     * @param majorType the major type of the string, should be either 0x40 or 0x60;
     * @param bytes the byte string to write, can be `null` in which case a byte-string of length <tt>0</tt> is written.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    private fun writeString(majorType: Int, bytes: ByteArray?) {
        val len = bytes?.size ?: 0
        writeType(majorType, len.toLong())
        for (i in 0 until len) {
            outputStream.write(bytes!![i].toInt())
        }
    }

    /**
     * Encodes and writes the major type indicator with a given payload (length).
     *
     * @param majorType the major type of the value to write, denotes what semantics the written value has;
     * @param value the value to write, values from [Long.MIN_VALUE] to [Long.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    private fun writeType(majorType: Int, value: Long) {
        writeUInt((majorType shl 5), value)
    }

    /**
     * Encodes and writes an unsigned integer value, that is, tries to encode it in a little bytes as possible.
     *
     * @param mt the major type of the value to write, denotes what semantics the written value has;
     * @param value the value to write, values from [Long.MIN_VALUE] to [Long.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    private fun writeUInt(mt: Int, value: Long) {
        if (value < 0x18L) {
            outputStream.write((mt.toLong() or value).toInt())
        } else if (value < 0x100L) {
            writeUInt8(mt, value.toInt())
        } else if (value < 0x10000L) {
            writeUInt16(mt, value.toInt())
        } else if (value < 0x100000000L) {
            writeUInt32(mt, value.toInt())
        } else {
            writeUInt64(mt, value)
        }
    }

    /**
     * Encodes and writes an unsigned 16-bit integer value
     *
     * @param mt the major type of the value to write, denotes what semantics the written value has;
     * @param value the value to write, values from [Long.MIN_VALUE] to [Long.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    private fun writeUInt16(mt: Int, value: Int) {
        outputStream.write(mt or CborConstants.TWO_BYTES)
        outputStream.write(value shr 8)
        outputStream.write(value and 0xFF)
    }

    /**
     * Encodes and writes an unsigned 32-bit integer value
     *
     * @param mt the major type of the value to write, denotes what semantics the written value has;
     * @param value the value to write, values from [Long.MIN_VALUE] to [Long.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    private fun writeUInt32(mt: Int, value: Int) {
        outputStream.write(mt or CborConstants.FOUR_BYTES)
        outputStream.write(value shr 24)
        outputStream.write(value shr 16)
        outputStream.write(value shr 8)
        outputStream.write(value and 0xFF)
    }


    /**
     * Encodes and writes an unsigned 64-bit integer value
     *
     * @param mt the major type of the value to write, denotes what semantics the written value has;
     * @param value the value to write, values from [Long.MIN_VALUE] to [Long.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    private fun writeUInt64(mt: Int, value: Long) {
        outputStream.write(mt or CborConstants.EIGHT_BYTES)
        outputStream.write((value shr 56).toInt())
        outputStream.write((value shr 48).toInt())
        outputStream.write((value shr 40).toInt())
        outputStream.write((value shr 32).toInt())
        outputStream.write((value shr 24).toInt())
        outputStream.write((value shr 16).toInt())
        outputStream.write((value shr 8).toInt())
        outputStream.write((value and 0xFF).toInt())
    }

    /**
     * Encodes and writes an unsigned 8-bit integer value
     *
     * @param mt the major type of the value to write, denotes what semantics the written value has;
     * @param value the value to write, values from [Long.MIN_VALUE] to [Long.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    private fun writeUInt8(mt: Int, value: Int) {
        outputStream.write(mt or CborConstants.ONE_BYTE)
        outputStream.write(value and 0xFF)
    }
}
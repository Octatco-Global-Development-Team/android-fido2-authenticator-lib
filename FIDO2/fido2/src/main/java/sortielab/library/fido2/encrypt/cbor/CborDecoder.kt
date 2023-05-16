/**
 * JACOB - CBOR implementation in Kotlin.
 *
 * (C) Copyright - 2023 - K.H. Saebyeol <snorlax@sortielab.com>
 *
 * Licensed under Apache License v2.0.
 */
package sortielab.library.fido2.encrypt.cbor

import sortielab.library.fido2.encrypt.cbor.CborType.Companion.getName
import sortielab.library.fido2.encrypt.cbor.CborType.Companion.valueOf
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.PushbackInputStream
import kotlin.math.pow

/**
 * Provides a decoder capable of handling CBOR encoded data from a {@link InputStream}.
 * @param inputStream the actual input stream to read the CBOR-encoded data from, cannot be <code>null</code>.
 */
@Suppress("unused")
class CborDecoder(private val inputStream: InputStream?) {
    private val mPushInputStream: PushbackInputStream

    /**
     * Creates a new {@link CborDecoder} instance.
     */
    init {
        if (inputStream == null) {
            throw IllegalArgumentException("InputStream cannot be null!")
        }
        mPushInputStream = if (inputStream is PushbackInputStream) {
            inputStream
        } else {
            PushbackInputStream(inputStream)
        }
    }

    @Throws(IOException::class)
    private fun fail(msg: String, vararg args: Any) {
        throw IOException(String.format(msg, *args))
    }

    private fun lengthToString(len: Int): String {
        return when {
            len < 0 -> {
                "no payload"
            }

            len == CborConstants.ONE_BYTE -> {
                "one byte"
            }

            len == CborConstants.TWO_BYTES -> {
                "two bytes"
            }

            len == CborConstants.FOUR_BYTES -> {
                "four bytes"
            }

            len == CborConstants.EIGHT_BYTES -> {
                "eight bytes"
            }

            else -> {
                "(unknown)"
            }
        }
    }

    /**
     * Peeks in the input stream for the upcoming type.
     *
     * @return the upcoming type in the stream, or `null` in case of an end-of-stream.
     * @throws IOException in case of I/O problems reading the CBOR-type from the underlying input stream.
     */
    @Throws(IOException::class)
    fun peekType(): CborType? {
        val p = mPushInputStream.read()
        if (p < 0) {
            // EOF, nothing to peek at...
            return null
        }
        mPushInputStream.unread(p)
        return valueOf(p)
    }

    /**
     * Prolog to reading an array value in CBOR format.
     *
     * @return the number of elements in the array to read, or <tt>-1</tt> in case of infinite-length arrays.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readArrayLength(): Long {
        return readMajorTypeWithSize(CborConstants.TYPE_ARRAY)
    }

    /**
     * Reads a boolean value in CBOR format.
     *
     * @return the read boolean.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readBoolean(): Boolean {
        val b: Int = readMajorType(CborConstants.TYPE_FLOAT_SIMPLE)
        if (b != CborConstants.FALSE && b != CborConstants.TRUE) {
            fail("Unexpected boolean value: %d!", b)
        }
        return b == CborConstants.TRUE
    }

    /**
     * Reads a "break"/stop value in CBOR format.
     *
     * @return always `null`.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readBreak(): Any? {
        readMajorTypeExact(
            CborConstants.TYPE_FLOAT_SIMPLE,
            CborConstants.BREAK
        )
        return null
    }

    /**
     * Reads a byte string value in CBOR format.
     *
     * @return the read byte string, never `null`. In case the encoded string has a length of <tt>0</tt>, an empty string is returned.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readByteString(): ByteArray {
        val len: Long = readMajorTypeWithSize(CborConstants.TYPE_BYTE_STRING)
        if (len < 0) {
            fail("Infinite-length byte strings not supported!")
        }
        if (len > Int.MAX_VALUE) {
            fail("String length too long!")
        }
        return readFully(ByteArray(len.toInt()))
    }

    /**
     * Prolog to reading a byte string value in CBOR format.
     *
     * @return the number of bytes in the string to read, or <tt>-1</tt> in case of infinite-length strings.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readByteStringLength(): Long {
        return readMajorTypeWithSize(CborConstants.TYPE_BYTE_STRING)
    }

    /**
     * Reads a double-precision float value in CBOR format.
     *
     * @return the read double value, values from [Float.MIN_VALUE] to [Float.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readDouble(): Double {
        readMajorTypeExact(
            CborConstants.TYPE_FLOAT_SIMPLE,
            CborConstants.DOUBLE_PRECISION_FLOAT
        )
        return java.lang.Double.longBitsToDouble(readUInt64())
    }

    /**
     * Reads a single-precision float value in CBOR format.
     *
     * @return the read float value, values from [Float.MIN_VALUE] to [Float.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readFloat(): Float {
        readMajorTypeExact(
            CborConstants.TYPE_FLOAT_SIMPLE,
            CborConstants.SINGLE_PRECISION_FLOAT
        )
        return java.lang.Float.intBitsToFloat(readUInt32().toInt())
    }


    /**
     * Reads a half-precision float value in CBOR format.
     *
     * @return the read half-precision float value, values from [Float.MIN_VALUE] to [Float.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readHalfPrecisionFloat(): Double {
        readMajorTypeExact(
            CborConstants.TYPE_FLOAT_SIMPLE,
            CborConstants.HALF_PRECISION_FLOAT
        )
        val half: Int = readUInt16()
        val exp = half shr 10 and 0x1f
        val mant = half and 0x3ff
        val value: Double = if (exp == 0) {
            mant * 2.0.pow(-24.0)
        } else if (exp != 31) {
            (mant + 1024) * 2.0.pow((exp - 25).toDouble())
        } else if (mant != 0) {
            Double.NaN
        } else {
            Double.POSITIVE_INFINITY
        }
        return if (half and 0x8000 == 0) value else -value
    }

    /**
     * Reads a signed or unsigned integer value in CBOR format.
     *
     * @return the read integer value, values from [Long.MIN_VALUE] to [Long.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readInt(): Long {
        val ib: Int = mPushInputStream.read()

        // in case of negative integers, extends the sign to all bits; otherwise zero...
        val ui: Long = expectIntegerType(ib)
        // in case of negative integers does a ones complement
        return ui xor readUInt(ib and 0x1f, false /* breakAllowed */)
    }

    /**
     * Reads a signed or unsigned 16-bit integer value in CBOR format.
     *
     * @read the small integer value, values from <tt>[-65536..65535]</tt> are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying output stream.
     */
    @Throws(IOException::class)
    fun readInt16(): Int {
        val ib: Int = mPushInputStream.read()

        // in case of negative integers, extends the sign to all bits; otherwise zero...
        val ui: Long = expectIntegerType(ib)
        // in case of negative integers does a ones complement
        return (ui xor readUIntExact(CborConstants.TWO_BYTES, ib and 0x1f)).toInt()
    }


    /**
     * Reads a signed or unsigned 32-bit integer value in CBOR format.
     *
     * @read the small integer value, values in the range <tt>[-4294967296..4294967295]</tt> are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying output stream.
     */
    @Throws(IOException::class)
    fun readInt32(): Long {
        val ib: Int = mPushInputStream.read()

        // in case of negative integers, extends the sign to all bits; otherwise zero...
        val ui: Long = expectIntegerType(ib)
        // in case of negative integers does a ones complement
        return ui xor readUIntExact(CborConstants.FOUR_BYTES, ib and 0x1f)
    }

    /**
     * Reads a signed or unsigned 64-bit integer value in CBOR format.
     *
     * @read the small integer value, values from [Long.MIN_VALUE] to [Long.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying output stream.
     */
    @Throws(IOException::class)
    fun readInt64(): Long {
        val ib: Int = mPushInputStream.read()

        // in case of negative integers, extends the sign to all bits; otherwise zero...
        val ui: Long = expectIntegerType(ib)
        // in case of negative integers does a ones complement
        return ui xor readUIntExact(CborConstants.EIGHT_BYTES, ib and 0x1f)
    }

    /**
     * Reads a signed or unsigned 8-bit integer value in CBOR format.
     *
     * @read the small integer value, values in the range <tt>[-256..255]</tt> are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying output stream.
     */
    @Throws(IOException::class)
    fun readInt8(): Int {
        val ib: Int = mPushInputStream.read()

        // in case of negative integers, extends the sign to all bits; otherwise zero...
        val ui: Long = expectIntegerType(ib)
        // in case of negative integers does a ones complement
        return (ui xor readUIntExact(CborConstants.ONE_BYTE, ib and 0x1f)).toInt()
    }

    /**
     * Prolog to reading a map of key-value pairs in CBOR format.
     *
     * @return the number of entries in the map, >= 0.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readMapLength(): Long {
        return readMajorTypeWithSize(CborConstants.TYPE_MAP)
    }

    /**
     * Reads a `null`-value in CBOR format.
     *
     * @return always `null`.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readNull(): Any? {
        readMajorTypeExact(
            CborConstants.TYPE_FLOAT_SIMPLE,
            CborConstants.NULL
        )
        return null
    }

    /**
     * Reads a single byte value in CBOR format.
     *
     * @return the read byte value.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readSimpleValue(): Byte {
        readMajorTypeExact(
            CborConstants.TYPE_FLOAT_SIMPLE,
            CborConstants.ONE_BYTE
        )
        return readUInt8().toByte()
    }


    /**
     * Reads a signed or unsigned small (&lt;= 23) integer value in CBOR format.
     *
     * @read the small integer value, values in the range <tt>[-24..23]</tt> are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying output stream.
     */
    @Throws(IOException::class)
    fun readSmallInt(): Int {
        val ib: Int = mPushInputStream.read()

        // in case of negative integers, extends the sign to all bits; otherwise zero...
        val ui: Long = expectIntegerType(ib)
        // in case of negative integers does a ones complement
        return (ui xor readUIntExact(-1, ib and 0x1f)).toInt()
    }

    /**
     * Reads a semantic tag value in CBOR format.
     *
     * @return the read tag value.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readTag(): Long {
        return readUInt(readMajorType(CborConstants.TYPE_TAG), false /* breakAllowed */)
    }

    /**
     * Reads an UTF-8 encoded string value in CBOR format.
     *
     * @return the read UTF-8 encoded string, never `null`. In case the encoded string has a length of <tt>0</tt>, an empty string is returned.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readTextString(): String {
        val len: Long = readMajorTypeWithSize(CborConstants.TYPE_TEXT_STRING)
        if (len < 0) {
            fail("Infinite-length text strings not supported!")
        }
        if (len > Int.MAX_VALUE) {
            fail("String length too long!")
        }
        return String(readFully(ByteArray(len.toInt())), Charsets.UTF_8)
    }

    /**
     * Prolog to reading an UTF-8 encoded string value in CBOR format.
     *
     * @return the length of the string to read, or <tt>-1</tt> in case of infinite-length strings.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readTextStringLength(): Long {
        return readMajorTypeWithSize(CborConstants.TYPE_TEXT_STRING)
    }

    /**
     * Reads an undefined value in CBOR format.
     *
     * @return always `null`.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    fun readUndefined(): Any? {
        readMajorTypeExact(
            CborConstants.TYPE_FLOAT_SIMPLE,
            CborConstants.UNDEFINED
        )
        return null
    }


    /**
     * Reads the next major type from the underlying input stream, and verifies whether it matches the given expectation.
     *
     * @param ib the expected major type, cannot be `null` (unchecked).
     * @return either <tt>-1</tt> if the major type was an signed integer, or <tt>0</tt> otherwise.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    private fun expectIntegerType(ib: Int): Long {
        val majorType = ib and 0xFF ushr 5
        if (majorType != CborConstants.TYPE_UNSIGNED_INTEGER && majorType != CborConstants.TYPE_NEGATIVE_INTEGER) {
            fail(
                "Unexpected type: %s, expected type %s or %s!",
                getName(majorType),
                getName(CborConstants.TYPE_UNSIGNED_INTEGER),
                getName(CborConstants.TYPE_NEGATIVE_INTEGER)
            )
        }
        return (-majorType).toLong()
    }


    /**
     * Reads the next major type from the underlying input stream, and verifies whether it matches the given expectation.
     *
     * @param majorType the expected major type, cannot be `null` (unchecked).
     * @return the read subtype, or payload, of the read major type.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    private fun readMajorType(majorType: Int): Int {
        val ib: Int = mPushInputStream.read()
        if (majorType != ib ushr 5 and 0x07) {
            fail("Unexpected type: %s, expected: %s!", getName(ib), getName(majorType))
        }
        return ib and 0x1F
    }

    /**
     * Reads the next major type from the underlying input stream, and verifies whether it matches the given expectations.
     *
     * @param majorType the expected major type, cannot be `null` (unchecked);
     * @param subtype the expected subtype.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    private fun readMajorTypeExact(majorType: Int, subtype: Int) {
        val st = readMajorType(majorType)
        if (st xor subtype != 0) {
            fail("Unexpected subtype: %d, expected: %d!", st, subtype)
        }
    }

    /**
     * Reads the next major type from the underlying input stream, verifies whether it matches the given expectation, and decodes the payload into a size.
     *
     * @param majorType the expected major type, cannot be `null` (unchecked).
     * @return the number of succeeding bytes, &gt;= 0, or <tt>-1</tt> if an infinite-length type is read.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    @Throws(IOException::class)
    private fun readMajorTypeWithSize(majorType: Int): Long {
        return readUInt(readMajorType(majorType), true /* breakAllowed */)
    }

    /**
     * Reads an unsigned integer with a given length-indicator.
     *
     * @param length the length indicator to use;
     * @return the read unsigned integer, as long value.
     * @throws IOException in case of I/O problems reading the unsigned integer from the underlying input stream.
     */
    @Throws(IOException::class)
    private fun readUInt(length: Int, breakAllowed: Boolean): Long {
        var result: Long = -1
        if (length < CborConstants.ONE_BYTE) {
            result = length.toLong()
        } else if (length == CborConstants.ONE_BYTE) {
            result = readUInt8().toLong()
        } else if (length == CborConstants.TWO_BYTES) {
            result = readUInt16().toLong()
        } else if (length == CborConstants.FOUR_BYTES) {
            result = readUInt32()
        } else if (length == CborConstants.EIGHT_BYTES) {
            result = readUInt64()
        } else if (breakAllowed && length == CborConstants.BREAK) {
            return -1
        }
        if (result < 0) {
            fail("Not well-formed CBOR integer found, invalid length: %d!", result)
        }
        return result
    }


    /**
     * Reads an unsigned 16-bit integer value
     *
     * @return value the read value, values from [Long.MIN_VALUE] to [Long.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    private fun readUInt16(): Int {
        val buf: ByteArray = readFully(ByteArray(2))
        return buf[0].toInt() and 0xFF shl 8 or (buf[1].toInt() and 0xFF)
    }

    /**
     * Reads an unsigned 32-bit integer value
     *
     * @return value the read value, values from [Long.MIN_VALUE] to [Long.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    private fun readUInt32(): Long {
        val buf: ByteArray = readFully(ByteArray(4))
        return (buf[0].toInt() and 0xFF shl 24 or (buf[1].toInt() and 0xFF shl 16) or (buf[2].toInt() and 0xFF shl 8) or (buf[3].toInt() and 0xFF)).toLong() and 0xffffffffL
    }


    /**
     * Reads an unsigned 64-bit integer value
     *
     * @return value the read value, values from [Long.MIN_VALUE] to [Long.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    private fun readUInt64(): Long {
        val buf = readFully(ByteArray(8))
        return buf[0].toLong() and 0xFFL shl 56 or (buf[1].toLong() and 0xFFL shl 48) or (buf[2].toLong() and 0xFFL shl 40) or (buf[3].toLong() and 0xFFL shl 32) or ( //
                buf[4].toLong() and 0xFFL shl 24) or (buf[5].toLong() and 0xFFL shl 16) or (buf[6].toLong() and 0xFFL shl 8) or (buf[7].toLong() and 0xFFL)
    }

    /**
     * Reads an unsigned 8-bit integer value
     *
     * @return value the read value, values from [Long.MIN_VALUE] to [Long.MAX_VALUE] are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    @Throws(IOException::class)
    private fun readUInt8(): Int {
        return mPushInputStream.read() and 0xff
    }

    /**
     * Reads an unsigned integer with a given length-indicator.
     *
     * @param length the length indicator to use;
     * @return the read unsigned integer, as long value.
     * @throws IOException in case of I/O problems reading the unsigned integer from the underlying input stream.
     */
    @Throws(IOException::class)
    private fun readUIntExact(expectedLength: Int, length: Int): Long {
        if (expectedLength == -1 && length >= CborConstants.ONE_BYTE || expectedLength >= 0 && length != expectedLength) {
            fail(
                "Unexpected payload/length! Expected %s, but got %s.", lengthToString(expectedLength),
                lengthToString(length)
            )
        }
        return readUInt(length, false /* breakAllowed */)
    }

    @Throws(IOException::class)
    private fun readFully(buf: ByteArray): ByteArray {
        val len = buf.size
        var n = 0
        val off = 0
        while (n < len) {
            val count: Int = mPushInputStream.read(buf, off + n, len - n)
            if (count < 0) {
                throw EOFException()
            }
            n += count
        }
        return buf
    }
}
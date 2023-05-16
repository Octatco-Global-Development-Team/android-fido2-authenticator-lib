/**
 * JACOB - CBOR implementation in Kotlin.
 *
 * (C) Copyright - 2023 - K.H. Saebyeol <snorlax@sortielab.com>
 *
 * Licensed under Apache License v2.0.
 */
package sortielab.library.fido2.encrypt.cbor

import java.lang.StringBuilder

/**
 * Represents the various major types in CBOR, along with their .
 * <p>
 * The major type is encoded in the upper three bits of each initial byte. The lower 5 bytes represent any additional information.
 * </p>
 */
class CborType(major: Int, additional: Int) {
    private val mMajor: Int = major
    private val mAdditional: Int = additional

    companion object {
        /**
         * Returns a descriptive string for the given major type.
         *
         * @param mt the major type to return as string, values from [0..7] are supported.
         * @return the name of the given major type, as String, never <code>null</code>.
         * @throws IllegalArgumentException in case the given major type is not supported.
         */
        fun getName(mt: Int): String {
            return when (mt) {
                CborConstants.TYPE_ARRAY -> "array"
                CborConstants.TYPE_BYTE_STRING -> "byte string"
                CborConstants.TYPE_FLOAT_SIMPLE -> "float/simple value"
                CborConstants.TYPE_MAP -> "map"
                CborConstants.TYPE_NEGATIVE_INTEGER -> "negative integer"
                CborConstants.TYPE_TAG -> "tag"
                CborConstants.TYPE_TEXT_STRING -> "text string"
                CborConstants.TYPE_UNSIGNED_INTEGER -> "unsigned integer"
                else -> throw IllegalArgumentException("Invalid major type: $mt")
            }
        }


        /**
         * Returns a descriptive string for the given major type.
         *
         * @param mt the major type to return as string, values from [0..7] are supported.
         * @return the name of the given major type, as String, never <code>null</code>.
         * @throws IllegalArgumentException in case the given major type is not supported.
         */
        fun valueOf(i: Int): CborType {
            return CborType(i and 0xff ushr 5, i and 0x1f)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val cborType = other as CborType
        return mMajor == cborType.mMajor && mAdditional == cborType.mAdditional
    }

    /**
     * @return the additional information of this type, as integer value from [0..31].
     */
    fun getAdditionalInfo(): Int {
        return mAdditional
    }

    /**
     * @return the major type, as integer value from [0..7].
     */
    fun getMajorType(): Int {
        return mMajor
    }

    override fun hashCode(): Int {
        val prime = 31
        var result = 1
        result = prime * result + mAdditional
        result = prime * result + mMajor
        return result
    }

    /**
     * @return <code>true</code> if this type allows for an infinite-length payload,
     *         <code>false</code> if only definite-length payloads are allowed.
     */
    fun isBreakAllowed(): Boolean {
        return (mMajor == CborConstants.TYPE_ARRAY) ||
                (mMajor == CborConstants.TYPE_BYTE_STRING) ||
                (mMajor == CborConstants.TYPE_MAP) ||
                (mMajor == CborConstants.TYPE_TEXT_STRING)
    }

    /**
     * Determines whether the major type of a given {@link CborType} equals the major type of this {@link CborType}.
     *
     * @param other the {@link CborType} to compare against, cannot be <code>null</code>.
     * @return <code>true</code> if the given {@link CborType} is of the same major type as this {@link CborType}, <code>false</code> otherwise.
     * @throws IllegalArgumentException in case the given argument was <code>null</code>.
     */
    fun isEqualType(other: CborType?): Boolean {
        if (other == null) {
            throw IllegalArgumentException("Parameter cannot be null!!")
        }
        return mMajor == other.mMajor
    }

    /**
     * Determines whether the major type of a given byte value (representing an encoded {@link CborType}) equals the major type of this {@link CborType}.
     *
     * @param encoded the encoded CBOR type to compare.
     * @return <code>true</code> if the given byte value represents the same major type as this {@link CborType}, <code>false</code> otherwise.
     */
    fun isEqualType(encoded: Int): Boolean {
        return mMajor == encoded and 0xff ushr 5
    }

    override fun toString(): String {
        val sb = StringBuilder()
        sb.append(getName(mMajor)).append('(').append(mAdditional).append(')')
        return sb.toString()
    }
}
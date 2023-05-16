/**
 * JACOB - CBOR implementation in Kotlin.
 *
 * (C) Copyright - 2023 - K.H. Saebyeol <snorlax@sortielab.com>
 *
 * Licensed under Apache License v2.0.
 */
package sortielab.library.fido2.encrypt.cbor

object CborConstants {
    /** Major type 0: unsigned integers.  */
    var TYPE_UNSIGNED_INTEGER = 0x00

    /** Major type 1: negative integers.  */
    var TYPE_NEGATIVE_INTEGER = 0x01

    /** Major type 2: byte string.  */
    var TYPE_BYTE_STRING = 0x02

    /** Major type 3: text/UTF8 string.  */
    var TYPE_TEXT_STRING = 0x03

    /** Major type 4: array of items.  */
    var TYPE_ARRAY = 0x04

    /** Major type 5: map of pairs.  */
    var TYPE_MAP = 0x05

    /** Major type 6: semantic tags.  */
    var TYPE_TAG = 0x06

    /** Major type 7: floating point, simple data types.  */
    var TYPE_FLOAT_SIMPLE = 0x07

    /** Denotes a one-byte value (uint8).  */
    var ONE_BYTE = 0x18

    /** Denotes a two-byte value (uint16).  */
    var TWO_BYTES = 0x19

    /** Denotes a four-byte value (uint32).  */
    var FOUR_BYTES = 0x1a

    /** Denotes a eight-byte value (uint64).  */
    var EIGHT_BYTES = 0x1b

    /** The CBOR-encoded boolean `false` value (encoded as "simple value": ).  */
    var FALSE = 0x14

    /** The CBOR-encoded boolean `true` value (encoded as "simple value":).  */
    var TRUE = 0x15

    /** The CBOR-encoded `null` value (encoded as "simple value": ).  */
    var NULL = 0x16

    /** The CBOR-encoded "undefined" value (encoded as "simple value": ).  */
    var UNDEFINED = 0x17

    /** Denotes a half-precision float (two-byte IEEE 754).  */
    var HALF_PRECISION_FLOAT = 0x19

    /** Denotes a single-precision float (four-byte IEEE 754).  */
    var SINGLE_PRECISION_FLOAT = 0x1a

    /** Denotes a double-precision float (eight-byte IEEE 754).  */
    var DOUBLE_PRECISION_FLOAT = 0x1b

    /** The CBOR-encoded "break" stop code for unlimited arrays/maps.  */
    var BREAK = 0x1f

    /** Semantic tag value describing date/time values in the standard format (UTF8 string, RFC3339).  */
    var TAG_STANDARD_DATE_TIME = 0

    /** Semantic tag value describing date/time values as Epoch timestamp (numeric, RFC3339).  */
    var TAG_EPOCH_DATE_TIME = 1

    /** Semantic tag value describing a positive big integer value (byte string).  */
    var TAG_POSITIVE_BIGINT = 2

    /** Semantic tag value describing a negative big integer value (byte string).  */
    var TAG_NEGATIVE_BIGINT = 3

    /** Semantic tag value describing a decimal fraction value (two-element array, base 10).  */
    var TAG_DECIMAL_FRACTION = 4

    /** Semantic tag value describing a big decimal value (two-element array, base 2).  */
    var TAG_BIGDECIMAL = 5

    /** Semantic tag value describing an expected conversion to base64url encoding.  */
    var TAG_EXPECTED_BASE64_URL_ENCODED = 21

    /** Semantic tag value describing an expected conversion to base64 encoding.  */
    var TAG_EXPECTED_BASE64_ENCODED = 22

    /** Semantic tag value describing an expected conversion to base16 encoding.  */
    var TAG_EXPECTED_BASE16_ENCODED = 23

    /** Semantic tag value describing an encoded CBOR data item (byte string).  */
    var TAG_CBOR_ENCODED = 24

    /** Semantic tag value describing an URL (UTF8 string).  */
    var TAG_URI = 32

    /** Semantic tag value describing a base64url encoded string (UTF8 string).  */
    var TAG_BASE64_URL_ENCODED = 33

    /** Semantic tag value describing a base64 encoded string (UTF8 string).  */
    var TAG_BASE64_ENCODED = 34

    /** Semantic tag value describing a regular expression string (UTF8 string, PCRE).  */
    var TAG_REGEXP = 35

    /** Semantic tag value describing a MIME message (UTF8 string, RFC2045).  */
    var TAG_MIME_MESSAGE = 36

    /** Semantic tag value describing CBOR content.  */
    var TAG_CBOR_MARKER = 55799
}
package dev.jegly.securitystate.data

/**
 * A deliberately small DER reader, just enough for the KeyMint attestation extension.
 *
 * We avoid pulling in BouncyCastle for this: the grammar we need is a handful of SEQUENCEs and
 * context-tagged primitives. The one subtlety is that the AuthorizationList tags run to 704+,
 * which forces the multi-byte ("high tag number") form.
 */
internal class Tlv(
    val tagClass: Int,
    val constructed: Boolean,
    val tagNumber: Int,
    val valueStart: Int,
    val valueEnd: Int,
)

internal class DerReader(
    private val buf: ByteArray,
    private var pos: Int,
    private val end: Int,
) {
    constructor(buf: ByteArray) : this(buf, 0, buf.size)

    fun hasNext(): Boolean = pos < end

    fun next(): Tlv {
        require(pos < end) { "DER: truncated at $pos" }
        val first = buf[pos++].toInt() and 0xFF
        val tagClass = (first and 0xC0) ushr 6
        val constructed = (first and 0x20) != 0
        var tagNumber = first and 0x1F
        if (tagNumber == 0x1F) {
            // High tag number form: base-128, big endian, continuation bit in the MSB.
            tagNumber = 0
            while (true) {
                require(pos < end) { "DER: truncated tag number" }
                val b = buf[pos++].toInt() and 0xFF
                tagNumber = (tagNumber shl 7) or (b and 0x7F)
                require(tagNumber <= 0xFFFF) { "DER: implausible tag number" }
                if (b and 0x80 == 0) break
            }
        }
        require(pos < end) { "DER: truncated length" }
        var len = buf[pos++].toInt() and 0xFF
        if (len and 0x80 != 0) {
            val n = len and 0x7F
            require(n in 1..4) { "DER: unsupported length form ($n bytes)" }
            require(pos + n <= end) { "DER: truncated long length" }
            len = 0
            repeat(n) { len = (len shl 8) or (buf[pos++].toInt() and 0xFF) }
            require(len >= 0) { "DER: negative length" }
        }
        val valueStart = pos
        val valueEnd = valueStart + len
        require(valueEnd in valueStart..end) { "DER: length overruns buffer" }
        pos = valueEnd
        return Tlv(tagClass, constructed, tagNumber, valueStart, valueEnd)
    }

    fun reader(t: Tlv): DerReader = DerReader(buf, t.valueStart, t.valueEnd)

    fun bytes(t: Tlv): ByteArray = buf.copyOfRange(t.valueStart, t.valueEnd)

    fun long(t: Tlv): Long {
        var r = 0L
        for (i in t.valueStart until t.valueEnd) r = (r shl 8) or (buf[i].toLong() and 0xFF)
        return r
    }

    fun boolean(t: Tlv): Boolean = t.valueEnd > t.valueStart && buf[t.valueStart].toInt() != 0

    fun string(t: Tlv): String = String(bytes(t), Charsets.UTF_8)

    /** Unwraps one level of EXPLICIT context tagging and returns the inner element's reader. */
    fun explicit(t: Tlv): Pair<DerReader, Tlv> {
        val inner = reader(t)
        return inner to inner.next()
    }
}

internal fun ByteArray.toHex(): String =
    joinToString("") { "%02x".format(it.toInt() and 0xFF) }

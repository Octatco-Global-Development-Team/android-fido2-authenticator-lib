package sortielab.library.fido2

import android.util.Log

object Dlog {
    var DEBUG = false

    private const val TAG = "FIDO2Authenticator"

    /** Log Level Error  */
    fun e(message: String?) {
        if (DEBUG) Log.e(
            TAG,
            buildLogMsg(message)
        )
    }

    /** Log Level Warning  */
    fun w(message: String?) {
        if (DEBUG) Log.w(
            TAG,
            buildLogMsg(message)
        )
    }

    /** Log Level Information  */
    fun i(message: String?) {
        if (DEBUG) Log.i(
            TAG,
            buildLogMsg(message)
        )
    }

    /** Log Level Debug  */
    fun d(message: String?) {
        if (DEBUG) Log.d(
            TAG,
            buildLogMsg(message)
        )
    }

    /** Log Level Verbose  */
    fun v(message: String?) {
        if (DEBUG) Log.v(
            TAG,
            buildLogMsg(message)
        )
    }


    private fun buildLogMsg(message: String?): String {
        val ste = Thread.currentThread().stackTrace[4]
        val sb = StringBuilder().apply {
            append("[")
            append(ste.fileName?:"FileNotFound.java".replace(".java", ""))
            append("::")
            append(ste.methodName)
            append("]")
            append(message)
        }
        return sb.toString()
    }
}
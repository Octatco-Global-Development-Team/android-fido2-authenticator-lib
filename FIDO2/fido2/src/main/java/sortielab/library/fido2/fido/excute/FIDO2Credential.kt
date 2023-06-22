@file:Suppress("unused")

package sortielab.library.fido2.fido.excute

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import sortielab.library.fido2.Dlog
import sortielab.library.fido2.RootApplication
import sortielab.library.fido2.room.repo.CredentialRepository
import java.io.IOException

object FIDO2Credential {
    /**
     * @param credentialId Want Delete FIDO Credential Id
     * @param origin Want Delete FIDO RPID
     * @param callback Return SQL Result
     */
    @Throws(IOException::class)
    fun deleteCredential(credentialId: String, origin: String, callback: FIDO2ResponseCallback) {
        CoroutineScope(Dispatchers.IO).launch {
            val repo = CredentialRepository(RootApplication.getInstance())
            kotlin.runCatching {
                repo.deleteCredential(origin, credentialId)
            }.onSuccess { result ->
                Dlog.i("SQL Result: $result")
                callback.onCredentialDelete(result)
            }.onFailure {
                it.printStackTrace()
                Dlog.e("Error: ${it.message}")
                callback.onCredentialDelete(false)
            }
        }
    }
}
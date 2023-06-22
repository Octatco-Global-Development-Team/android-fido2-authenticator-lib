package sortielab.library.fido2.room.repo

import android.app.Application
import androidx.annotation.WorkerThread
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import sortielab.library.fido2.Dlog
import sortielab.library.fido2.encrypt.tools.CommonUtil
import sortielab.library.fido2.room.dao.FidoCredentialDAO
import sortielab.library.fido2.room.databases.FidoCredentialDataBase
import sortielab.library.fido2.room.entity.PublicKeyCredential
import java.io.IOException

class CredentialRepository(application: Application) {
    private var credentialDAO: FidoCredentialDAO

    init {
        val db = FidoCredentialDataBase.getInstance(application)
        credentialDAO = db.credentialDAO()
    }

    fun getCredentialData(rpid: String, credId: String): PublicKeyCredential? {
        return credentialDAO.getCredentialByRpidCredentialId(rpid, credId)
    }

    @WorkerThread
    suspend fun insert(publicKeyCredential: PublicKeyCredential): Long {
        return credentialDAO.saveCredential(publicKeyCredential)
    }

    @WorkerThread
    suspend fun update(publicKeyCredential: PublicKeyCredential) {
        return credentialDAO.updateCredentialInfo(publicKeyCredential)
    }

    @Throws(IOException::class)
    @WorkerThread
    suspend fun deleteCredential(origin: String, credId: String): Boolean {
        val rpid = CommonUtil.getTldPlusOne(origin) ?: return false
        return deleteQueryResult(rpid, credId)
    }

    @Throws(IOException::class)
    private suspend fun deleteQueryResult(rpid: String, credId: String): Boolean = withContext(Dispatchers.IO) {
        var result = false
        getCredentialData(rpid, credId)?.let { cred ->
            kotlin.runCatching { credentialDAO.deleteCredential(cred) }.onSuccess { res ->
                Dlog.i("Query Result: $res")
                if (res > 0) {
                    result = true
                }
            }.onFailure {
                Dlog.e("DB SQL Error: ${it.message}")
            }
        }

        result
    }
}
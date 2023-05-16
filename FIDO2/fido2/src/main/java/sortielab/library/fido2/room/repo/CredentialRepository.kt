package sortielab.library.fido2.room.repo

import android.app.Application
import androidx.annotation.WorkerThread
import sortielab.library.fido2.room.dao.FidoCredentialDAO
import sortielab.library.fido2.room.databases.FidoCredentialDataBase
import sortielab.library.fido2.room.entity.PublicKeyCredential

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

    @WorkerThread
    suspend fun delete(publicKeyCredential: PublicKeyCredential) {
        return credentialDAO.deleteCredential(publicKeyCredential)
    }
}
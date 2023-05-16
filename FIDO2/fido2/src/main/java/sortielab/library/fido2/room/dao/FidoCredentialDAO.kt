package sortielab.library.fido2.room.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import sortielab.library.fido2.room.entity.PublicKeyCredential

@Dao
interface FidoCredentialDAO {
    @Query("SELECT * FROM public_key_credential WHERE rpid = :rpid AND credential_id = :credId")
    fun getCredentialByRpidCredentialId(rpid: String, credId: String): PublicKeyCredential?

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun saveCredential(publicKeyCredential: PublicKeyCredential): Long

    @Update
    suspend fun updateCredentialInfo(publicKeyCredential: PublicKeyCredential)

    @Delete
    suspend fun deleteCredential(publicKeyCredential: PublicKeyCredential)
}
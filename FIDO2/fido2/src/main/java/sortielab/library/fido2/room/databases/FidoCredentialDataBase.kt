package sortielab.library.fido2.room.databases

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import sortielab.library.fido2.room.dao.FidoCredentialDAO
import sortielab.library.fido2.room.entity.PublicKeyCredential

@Database(
    entities = [PublicKeyCredential::class],
    version = 1,
    exportSchema = false,
)
abstract class FidoCredentialDataBase : RoomDatabase() {
    abstract fun credentialDAO(): FidoCredentialDAO

    companion object {
        private lateinit var instance: FidoCredentialDataBase

        fun getInstance(ctx: Context): FidoCredentialDataBase {
            synchronized(FidoCredentialDataBase::class) {
                instance = Room.databaseBuilder(
                    ctx.applicationContext,
                    FidoCredentialDataBase::class.java,
                    "fido_credential"
                ).fallbackToDestructiveMigration().build()
            }
            return instance
        }
    }
}
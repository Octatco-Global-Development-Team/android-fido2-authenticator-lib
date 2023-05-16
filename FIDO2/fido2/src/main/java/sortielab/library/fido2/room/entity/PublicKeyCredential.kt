package sortielab.library.fido2.room.entity


import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import androidx.room.TypeConverter
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.util.Date

@Entity(
    tableName = "public_key_credential",
    indices = [Index(value = ["rpid", "userid", "credential_id"], unique = true)]
)
data class PublicKeyCredential(
    @PrimaryKey(autoGenerate = true) var id: Long,

    // Part of the FIDO2 specification, but local to RoomDB
    var counter: Int,

    /***** Required parts of Public Key Credential Source *****/
    var type: String = "",
    var userid: String = "",
    @ColumnInfo(name = "credential_id") var credentialId: String = "",
    var username: String = "",
    var rpid: String = "",
    @ColumnInfo(name = "key_alias") var keyAlias: String = "",
    @ColumnInfo(name = "key_origin") var keyOrigin: String = "",
    @ColumnInfo(name = "key_algorithm") var keyAlgorithm: String = "",
    @ColumnInfo(name = "key_size") var keySize: Int? = null,
    @ColumnInfo(name = "se_module") var seModule: String = "",
    @ColumnInfo(name = "public_key") var publicKey: String = "",
    @ColumnInfo(name = "user_handle") var userHandle: String = "",
    @ColumnInfo(name = "display_name") var displayName: String = "",
    @ColumnInfo(name = "authenticator_data") var authenticatorData: String = "",
    @ColumnInfo(name = "client_data_json") var clientDataJson: String = "",
    @ColumnInfo(name = "json_attestation") var jsonAttestation: String = "",
    @ColumnInfo(name = "cbor_attestation") var cborAttestation: String = "",

    // Not part of the FIDO2 specification
    @ColumnInfo(name = "create_date") var createDate: Long = 0,
    @ColumnInfo(name = "webauthn_origin") var origin: String = ""
) {
    override fun toString(): String {
        return jacksonObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(this)
    }

    fun setCreateDate(createDate: Date) {
        this.createDate = dateToTimestamp(createDate) ?: 0
    }

    @TypeConverter
    fun fromTimestamp(varue: Long?): Date? {
        return if (varue == null) null else Date(varue)
    }

    @TypeConverter
    fun dateToTimestamp(date: Date?): Long? {
        return date?.time
    }
}

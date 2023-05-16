package sortielab.library.fido2.fido.excute

import android.content.Context
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import sortielab.library.fido2.encrypt.tools.FidoConstants
import java.util.concurrent.Executor

class UserAuthenticate(activity: FragmentActivity, type: String) {
    var bioCallback: BioCallback? = null
    lateinit var context: Context
    private var executor: Executor
    private var biometricPrompt: BiometricPrompt
    private var promptInfo: BiometricPrompt.PromptInfo

    init {
        executor = ContextCompat.getMainExecutor(activity.baseContext)
        promptInfo = createBioPromptInfo(type)
        biometricPrompt = createBioPrompt(activity)
    }

    private fun createBioPrompt(activity: FragmentActivity): BiometricPrompt {
        return BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                bioCallback?.onFailed()
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                sortielab.library.fido2.Dlog.i("User Authenticate with ${result.authenticationType}")
                bioCallback?.onSuccess()
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                bioCallback?.onFailed()
            }
        })
    }

    private fun createBioPromptInfo(type: String): BiometricPrompt.PromptInfo {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(
                    if (type == FidoConstants.USER_AUTHENTICATE_MODE_CREATE) {
                        "FIDO2 등록을 진행합니다."
                    } else {
                        "FIDO2 인증을 진행합니다."
                    }
                )
                .setSubtitle(
                    if (type == FidoConstants.USER_AUTHENTICATE_MODE_CREATE) {
                        "사용자 본인 확인을 통해 FIDO2 인증키를 생성합니다."
                    } else {
                        "사용자 본인 확인을 통해 FIDO2 인증을 진행합니다."
                    }
                )
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build()
        } else {
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(
                    if (type == FidoConstants.USER_AUTHENTICATE_MODE_CREATE) {
                        "FIDO2 등록을 진행합니다."
                    } else {
                        "FIDO2 인증을 진행합니다."
                    }
                )
                .setSubtitle(
                    if (type == FidoConstants.USER_AUTHENTICATE_MODE_CREATE) {
                        "사용자 본인 확인을 통해 FIDO2 인증키를 생성합니다."
                    } else {
                        "사용자 본인 확인을 통해 FIDO2 인증을 진행합니다."
                    }
                )
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK)
                .setNegativeButtonText("Cancel")
                .build()
        }
    }

    fun authenticate() {
        sortielab.library.fido2.Dlog.d("authenticateEnable()")

        val textStatus: String
        val biometricManager = BiometricManager.from(context)
//        when (biometricManager.canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)) {
        when (biometricManager.canAuthenticate(BiometricManager.Authenticators.DEVICE_CREDENTIAL)) {
            //생체 인증 가능
            BiometricManager.BIOMETRIC_SUCCESS -> textStatus = "App can authenticate using biometrics."

            //기기에서 생체 인증을 지원하지 않는 경우
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                textStatus = "No biometric features available on this device."
//                viewEvent(BTN_EVENT_FINGERPRINT_CHECK_FAIL)
            }

            //현재 생체 인증을 사용할 수 없는 경우
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                textStatus = "Biometric features are currently unavailable."
//                viewEvent(BTN_EVENT_FINGERPRINT_CHECK_FAIL)
            }

            //생체 인식 정보가 등록되어 있지 않은 경우
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                textStatus = "Prompts the user to create credentials that your app accepts."

//                val dialogBuilder = AlertDialog.Builder(context)
//                dialogBuilder
//                    .setTitle(R.string.app_name)
//                    .setMessage("지문 등록이 필요합니다. 지문등록 설정화면으로 이동하시겠습니까?")
//                    .setPositiveButton("확인") { dialog, _ -> viewEvent(EVENT_GO_FINGERPRINT_SETTING) }
//                    .setNegativeButton("취소") { dialog, _ -> dialog.cancel() }
//                dialogBuilder.show()
            }

            //기타 실패
            else -> {
                val enable = biometricManager.canAuthenticate(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                sortielab.library.fido2.Dlog.i("Enable: $enable")
                textStatus = "Fail Biometric facility"
            }
        }

        sortielab.library.fido2.Dlog.i("Biometric Check Status: $textStatus")

        goAuthenticate()
    }

    private fun goAuthenticate() {
        promptInfo.let {
            biometricPrompt.authenticate(it)  //인증 실행
        }
    }
}
package sortielab.library.fido2

import android.app.Application
import android.content.res.Resources
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class RootApplication: Application() {
        companion object {
        private lateinit var res: Resources
        private lateinit var instance: Application

        fun getInstance(): Application {
            return instance
        }

        fun getResource(): Resources {
            return res
        }

        fun libraryLinkApplication(app: Application, debug: Boolean) {
            Dlog.DEBUG = debug
            Dlog.i("Root Created")
            instance = app
            res = instance.resources
        }
    }
    override fun onCreate() {
        super.onCreate()

        // Add Bouncy Castle provider during application startup
        Security.addProvider(BouncyCastleProvider())

//        // Any other initialization logic
//        libraryLinkApplication(this, BuildConfig.DEBUG)
    }
}
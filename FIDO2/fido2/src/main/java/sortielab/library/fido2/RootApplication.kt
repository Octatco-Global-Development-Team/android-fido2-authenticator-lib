package sortielab.library.fido2

import android.app.Application
import android.content.res.Resources

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
}
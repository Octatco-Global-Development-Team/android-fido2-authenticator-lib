interface Dependencies {
    object AndroidDefault {
        const val kotlinCore = "androidx.core:core-ktx:${Versions.kotlinCore}"
        const val appCompat = "androidx.appcompat:appcompat:${Versions.appCompat}"
        const val material = "com.google.android.material:material:${Versions.googleMaterial}"
        const val jUnit = "junit:junit:4.13.2"
        const val androidTest = "androidx.test.ext:junit:1.1.5"
        const val testCore = "androidx.test.espresso:espresso-core:3.5.1"
        const val constraintLayout = "androidx.constraintlayout:constraintlayout:2.1.4"
    }

    object AndroidRoom {
        const val roomRuntime = "androidx.room:room-runtime:${Versions.androidRoom}"
        const val roomCompiler = "androidx.room:room-compiler:${Versions.androidRoom}"
        const val roomKtx = "androidx.room:room-ktx:${Versions.androidRoom}"
    }

    object Encrypt {
        const val bouncyCastle = "org.bouncycastle:bcpkix-jdk15on:1.70"
        const val securityCrypto = "androidx.security:security-crypto:1.0.0"
        const val biometric = "androidx.biometric:biometric:1.1.0"
    }

    object GSON {
        const val jackson = "com.fasterxml.jackson.module:jackson-module-kotlin:2.15.0"
        const val gsonCore = "com.google.code.gson:gson:2.10.1"
    }
}



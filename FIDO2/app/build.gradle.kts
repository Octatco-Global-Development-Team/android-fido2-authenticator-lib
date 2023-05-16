@file:Suppress("UnstableApiUsage")

plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "saebyeol.library.fido2"
    compileSdk = Apps.compileSdk

    defaultConfig {
        applicationId = "saebyeol.library.fido2"
        minSdk = Apps.minSdk
        targetSdk = Apps.targetSdk
        versionCode = Apps.versionCode
        versionName = Apps.versionName

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android.txt"), "proguard-rules.pro")
        }
        getByName("debug") {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_11.toString()
    }
}

dependencies {
   Dependencies.AndroidDefault.run {
        implementation(this.kotlinCore)
        implementation(this.appCompat)
        implementation(this.material)
        implementation(this.constraintLayout)
        testImplementation(this.jUnit)
        androidTestImplementation(this.androidTest)
        androidTestImplementation(this.testCore)
    }
}
@file:Suppress("UnstableApiUsage")

plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "sortielab.library.example"
    compileSdk = Apps.compileSdk

    defaultConfig {
        applicationId = "sortielab.library.example"
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
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
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
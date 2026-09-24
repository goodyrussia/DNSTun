plugins {
    id("com.android.application")
}

android {
    namespace = "com.dnstun.app"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.dnstun.app"
        minSdk = 26
        targetSdk = 37
        versionCode = 11
        versionName = "4.0.0"
    }

    signingConfigs {
        val ks = System.getenv("DNSTUN_KEYSTORE")
        if (!ks.isNullOrBlank()) {
            create("release") {
                storeFile = file(ks)
                storePassword = System.getenv("DNSTUN_STORE_PASSWORD")
                keyAlias = System.getenv("DNSTUN_KEY_ALIAS")
                keyPassword = System.getenv("DNSTUN_KEY_PASSWORD")
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            isShrinkResources = false
            signingConfig = signingConfigs.findByName("release")
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources.excludes += setOf("META-INF/*.kotlin_module")
        // libdnstun.so is not a loadable library -- it is an ELF EXECUTABLE that
        // DnstunService execs from nativeLibraryDir. With the default
        // useLegacyPackaging=false, AGP stores .so files page-aligned inside the
        // APK and NEVER extracts them to disk, so nativeLibraryDir is empty and
        // the engine "goes missing" on every fresh install.
        jniLibs.useLegacyPackaging = true
    }
}

dependencies {
}

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
        versionCode = 4
        versionName = "2.3.0"
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
    }
}

dependencies {
}

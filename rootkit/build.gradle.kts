import org.jetbrains.kotlin.cfg.pseudocode.and

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    `maven-publish`
}

android {
    namespace = "com.ssithara.rootkit"
    compileSdk = 36
    ndkVersion = "27.0.12077973"

    buildFeatures {
        prefab = true
    }

    defaultConfig {
        minSdk = 24

        externalNativeBuild.ndkBuild {
            arguments += "-j${Runtime.getRuntime().availableProcessors()}"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            consumerProguardFiles("consumer-rules.pro")
        }
    }

//    externalNativeBuild.ndkBuild {
//        path("src/main/cpp/Android.mk")
//    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = "11"
    }
}

tasks.register("prepareKotlinBuildScriptModel") {}

dependencies {
//    implementation("com.android.tools.build:apkzlib:7.2.2")
//    implementation("io.github.vvb2060.ndk:xposeddetector:2.2")
//    implementation("com.google.code.gson:gson:2.10.1")
//    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
//    implementation("androidx.annotation:annotation:1.7.1")

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

publishing {
    publications {
        create<MavenPublication>("release") {
            groupId = "com.ssithara"
            artifactId = "rootkit"
            version = "1.0.0"

            afterEvaluate {
                from(components["release"])
            }
        }
    }
}
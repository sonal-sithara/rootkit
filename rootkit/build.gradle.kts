plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    `maven-publish`
}

android {
    namespace = "com.ssithara.rootkit"
    compileSdk = 36
    ndkVersion = "27.0.12077973"

    defaultConfig {
        minSdk = 24

        externalNativeBuild.ndkBuild {
            arguments += "-j${Runtime.getRuntime().availableProcessors()}"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            consumerProguardFiles("consumer-rules.pro")
        }
    }

    buildFeatures {
        prefab = true
    }

    externalNativeBuild.ndkBuild {
        path("src/main/cpp/Android.mk")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = "11"
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    implementation(libs.rootbeer.lib)
    implementation(libs.xposeddetector)

    // Periodic checks dependencies
    api(libs.kotlinx.coroutines.android)
    api(libs.androidx.lifecycle.process)
}

tasks.register<Jar>("sourcesJar") {
    archiveClassifier.set("sources")
    from(android.sourceSets["main"].java.srcDirs)
}

tasks.register<Jar>("javadocJar") {
    archiveClassifier.set("javadoc")
    // Empty stub — JitPack and some consumers require a javadoc JAR
}

publishing {
    publications {
        create<MavenPublication>("release") {
            groupId = "com.ssithara"
            artifactId = "rootkit"
            version = project.property("LIBRARY_VERSION") as String

            afterEvaluate {
                from(components["release"])
            }

            artifact(tasks["sourcesJar"])
            artifact(tasks["javadocJar"])

            pom {
                name.set("RootKit")
                description.set("Android security detection library for root, runtime tampering, and environment threats")
                url.set("https://github.com/ssithara/rootkit")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("ssithara")
                        name.set("Sonal Sithara")
                    }
                }
                scm {
                    connection.set("scm:git:github.com/ssithara/rootkit.git")
                    url.set("https://github.com/ssithara/rootkit")
                }
            }
        }
    }
}

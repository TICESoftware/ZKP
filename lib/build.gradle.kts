plugins {
    alias(libs.plugins.jvm)
    `java-library`
    `maven-publish`
}

group = "software.tice"
version = "1.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testImplementation(libs.junit.jupiter.engine)

    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.kotlincrypto:secure-random:0.2.0")
    implementation("com.nimbusds:nimbus-jose-jwt:9.37.3")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("ZKP") {
            groupId = "software.tice.zkp"
            artifactId = "zkp"
            version = "1.0"

            from(components["java"])
        }
    }
}

plugins {
    id("java")
    `java-library`                // Java 라이브러리 플러그인 추가
    `maven-publish`               // JitPack 배포를 위한 플러그인
}

group = "org.innercircle.parksay"
version = "0.0.3"

java {
    withSourcesJar()
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.test {
    useJUnitPlatform()
}


//publishing {
//    publications {
//        create<MavenPublication>("mavenJava") {
//            from(components["java"])
//        }
//    }
//}



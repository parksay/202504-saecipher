# SaeCipher

---
## 💡 소개
**SaeCipher**는 간단하게 사용할 수 있는 암호화 라이브러리입니다. 인코딩하고 암호화하고 디코딩하고 복호화하고 그러한 복잡한 과정을 생략할 수 있도록 해줍니다.
---

## 📌 주요 기능
- AES 256 암호화 및 복호화 지원
- RSA 2048 암호화 및 복호화 지원
- 키 생성
- 문자열 데이터를 암복호화 하여 문자열로 리턴
- RSA 기반 전자 서명 기능
---

## 🛠 설치 방법

#### maven
```xml
<!-- add to pom.xml -->
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<!-- add dependency -->
<dependency>
    <groupId>com.github.parksay</groupId>
    <artifactId>202504-saecipher</artifactId>
    <version>0.1.1</version>
</dependency>
```
️
#### Gradle
```groovy
repositories {
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'com.github.parksay:SaeCipher:0.1.1'
}
```

#### gradle.kts
```kotlin
repositories {
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    implementation("com.github.parksay:SaeCipher:0.1.1")
}
```

## 🚀 사용 예시
```java
import org.innercircle.saecipher.SAECipher;
import org.innercircle.saecipher.SAECipherKey;
import org.innercircle.saecipher.SAECipherType;


public void example() {
        String resiNum = "123456-1234567";
        String msg = "Hello world!";

        //
        // encrypt and decrypt with aes
        SAECipherKey keyAES = SAECipher.generateKey(SAECipherType.AES_256);
        String encryptedAes = SAECipher.encrypt(SAECipherType.AES_256, keyAES, resiNum);
        String decryptedAes = SAECipher.decrypt(SAECipherType.AES_256, keyAES, encryptedAes);

        //
        // encrypt and decrypt with rsa
        SAECipherKey keyRSA = SAECipher.generateKey(SAECipherType.RSA_2048);
        String encryptedRsa = SAECipher.encrypt(SAECipherType.RSA_2048, keyRSA, resiNum);
        String decryptedRsa = SAECipher.decrypt(SAECipherType.RSA_2048, keyRSA, encryptedRsa);

        //
        // sign and verify
        SAECipherKey keyRSA = SAECipher.generateKey(SAECipherType.RSA_2048);
        String signed =  SAECipher.sign(keyRSA, msg);
        boolean isVerified = SAECipher.verify(keyRSA, msg, signed);

        }
```
---



## 📜 라이센스
MIT License
---


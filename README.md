# android-fido2-authenticator-lib
This project is licensed under the terms of the GPL v3 license.

---

## Test Locally

1) After making changes to the library code, publish the library locally on your PC with the command below.

- From the project root, move to the FIDO2 (library) folder
```shell
cd FIDO2
```

- publish locally
```shell
./gradlew publishToMavenLocal
```

2) In the **settings.gradle** file of the **Android App which consumes this library**, make sure you uncomment the mavenLocal() to use the local version of the library.

```kotlin
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenLocal() // Uncomment to test with local Maven Repo
        google()
        mavenCentral()
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/Octatco-Global-Development-Team/android-fido2-authenticator-lib")
            credentials {
                username = githubProperties.getProperty("github_username") ?: System.getenv("github_username")
                password = githubProperties.getProperty("github_access_token") ?: System.getenv("github_access_token")
            }
        }
    }
}
```

3) In the Android App, refresh the Gradle dependencies.

Repeat these steps each time you want to test new changes you made to the FIDO2 Library code.

---

## Publishing an Update to the library

1) After testing is complete, update the moduleVersion (**Apps.kt**) and push the changes to github. (It's a good idea to also add a release tag)

```kotlin
const val moduleVersion = "1.0.7"
```

2) Publish the library update

```shell
cd FIDO2
```

```shell
./gradlew publish
```

### Update the Android Mobile App after a library update


- In the **Versions.kt** file, update the version number

```kotlin
const val fido = "1.0.7"
```

- In the **settings.gradle** file, make sure the mavenLocal() line is commented
```kotlin
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        //mavenLocal() // Uncomment to test with local Maven Repo
        google()
        mavenCentral()
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/Octatco-Global-Development-Team/android-fido2-authenticator-lib")
            credentials {
                username = githubProperties.getProperty("github_username") ?: System.getenv("github_username")
                password = githubProperties.getProperty("github_access_token") ?: System.getenv("github_access_token")
            }
        }
    }
}
```

- Sync the gradle files

- Push to Github

- [OPTIONAL] Publish update to playstore / build new .apk file (depending on requirements)


---
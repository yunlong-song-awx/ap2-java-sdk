# ap2-java-sdk
JAVA SDK for Agent Payments Protocol (AP2) https://github.com/google-agentic-commerce/AP2

[![Maven Central](https://img.shields.io/maven-central/v/io.github.yunlong-song-awx/ap2-java-sdk?color=blue)](https://central.sonatype.com/artifact/io.github.yunlong-song-awx/ap2-java-sdk)
[![GitHub Package](https://img.shields.io/badge/github-packages-blue?logo=github)](https://github.com/yunlong-song-awx/ap2-java-sdk/packages/)

## Usage

### Maven Central
```groovy
repositories {
    mavenCentral()
}

dependencies {
    implementation 'io.github.yunlong-song-awx:ap2-java-sdk:0.1.9'
}
```

### GitHub Packages
```groovy
repositories {
    maven {
        url = uri('https://maven.pkg.github.com/yunlong-song-awx/ap2-java-sdk')
        credentials {
            username = project.findProperty('gpr.user') ?: System.getenv('GITHUB_ACTOR')
            password = project.findProperty('gpr.token') ?: System.getenv('GITHUB_TOKEN')
        }
    }
}

dependencies {
    implementation 'io.github.yunlong-song-awx:ap2-java-sdk:0.1.9'
}
```

### Maven
```xml
<dependency>
  <groupId>io.github.yunlong-song-awx</groupId>
  <artifactId>ap2-java-sdk</artifactId>
  <version>0.1.9</version>
</dependency>
```

## Release

1. Go to **Actions** → **Gradle Package** → **Run workflow**
2. Select `main` branch → **Run workflow**
3. The workflow will:
   - Strip `-SNAPSHOT` suffix and publish the release version
   - Create a git tag (e.g. `v0.1.5`)
   - Bump the version in `build.gradle` to the next snapshot
   - Push the tag and version bump commit

# ap2-java-sdk
JAVA SDK for Agent Payments Protocol (AP2) https://github.com/google-agentic-commerce/AP2

## Usage

### Gradle
```groovy
repositories {
    mavenCentral()
}

dependencies {
    implementation 'io.github.yunlong-song-awx:ap2-java-sdk:0.1.8'
}
```

### Maven
```xml
<dependency>
  <groupId>io.github.yunlong-song-awx</groupId>
  <artifactId>ap2-java-sdk</artifactId>
  <version>0.1.8</version>
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

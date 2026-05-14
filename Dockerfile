FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /workspace
COPY gradlew settings.gradle.kts build.gradle.kts ./
COPY gradle ./gradle
RUN ./gradlew --version
COPY src ./src
RUN ./gradlew bootJar --no-daemon -x test

FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S auth0lite && adduser -S auth0lite -G auth0lite
WORKDIR /app
COPY --from=build /workspace/build/libs/*.jar app.jar
USER auth0lite
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --retries=10 --start-period=30s \
    CMD wget --spider -q http://localhost:8080/actuator/health || exit 1
ENTRYPOINT ["java", "-jar", "app.jar"]

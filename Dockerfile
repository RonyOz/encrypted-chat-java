FROM eclipse-temurin:11-jdk-alpine AS builder
WORKDIR /app
COPY src/ src/
COPY scripts/ scripts/
RUN mkdir -p build/classes && \
    find src/main/java -name '*.java' | sort > build/main-sources.txt && \
    javac --release 11 -encoding UTF-8 -d build/classes @build/main-sources.txt && \
    jar --create --file build/encrypted-chat.jar \
        --main-class com.encryptedchat.ChatApplication \
        -C build/classes . && \
    jar --create --file build/observer.jar \
        --main-class com.encryptedchat.observer.SessionObserverApp \
        -C build/classes .

FROM eclipse-temurin:11-jre-alpine
WORKDIR /app
COPY --from=builder /app/build/encrypted-chat.jar .
COPY --from=builder /app/build/observer.jar .
ENTRYPOINT ["java", "-jar", "encrypted-chat.jar"]

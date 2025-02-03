FROM alpine/java:21-jdk

RUN apk --no-cache add curl

WORKDIR /app

ADD target/config-server-1.0-SNAPSHOT.jar .

CMD ["java", "-jar", "config-server-1.0-SNAPSHOT.jar"]
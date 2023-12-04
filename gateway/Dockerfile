FROM openjdk:17

WORKDIR /app

ADD target/gateway-1.0-SNAPSHOT.jar .
ADD www_avdeev-sa_ru.crt .

RUN keytool -noprompt -storepass changeit -keystore /usr/java/openjdk-17/lib/security/cacerts -import -file www_avdeev-sa_ru.crt -alias www_avdeev

CMD ["java", "-jar", "gateway-1.0-SNAPSHOT.jar"]
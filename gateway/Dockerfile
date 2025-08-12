FROM alpine/java:21-jdk

WORKDIR /app

ADD target/gateway-1.0-SNAPSHOT.jar .
ADD /etc/ssl/certs/__avdeev-sa_ru.crt .

RUN keytool -noprompt -storepass changeit -keystore $JAVA_HOME/lib/security/cacerts -import -file __avdeev-sa_ru.crt -alias www_avdeev

CMD ["java", "-jar", "gateway-1.0-SNAPSHOT.jar"]

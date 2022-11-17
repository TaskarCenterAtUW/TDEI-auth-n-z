FROM openjdk:17-jdk-slim-buster
ARG JAR_FILE=target/*.jar
ARG environment
COPY ${JAR_FILE} application.jar
EXPOSE 8080
ENTRYPOINT ["java", "-Dspring.profiles.active=${environment}", "-jar","/application.jar"]
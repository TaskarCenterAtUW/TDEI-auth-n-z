# Use an official OpenJDK runtime as the base image
FROM openjdk:17-jdk-slim-buster as builder

# Set the working directory inside the Docker image
WORKDIR /app

# Install Maven 3.8
RUN apt-get update && \
    apt-get install -y wget && \
    wget https://apache.osuosl.org/maven/maven-3/3.8.8/binaries/apache-maven-3.8.8-bin.tar.gz && \
    tar -xzf apache-maven-3.8.8-bin.tar.gz -C /opt && \
    ln -s /opt/apache-maven-3.8.8 /opt/maven && \
    ln -s /opt/maven/bin/mvn /usr/local/bin/mvn && \
    rm -f apache-maven-3.8.8-bin.tar.gz

# Copy the application source code and pom.xml
COPY . .

# Build the application using Maven
RUN mvn clean package -DskipTests

FROM openjdk:17-jdk-slim-buster
#Create empty jar file
RUN touch application.jar
#Copy generated jar and overwrite application.jar
COPY --from=builder /app/target/*.jar ./application.jar

# Expose the application port
EXPOSE 8080

# Define the command to run the Spring Boot application
CMD ["java", "-jar", "application.jar"]

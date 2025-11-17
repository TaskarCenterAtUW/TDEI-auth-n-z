# Use an official OpenJDK runtime as the base image
FROM eclipse-temurin:17-jdk-jammy as builder

# Set the working directory inside the Docker image
WORKDIR /app

# Install Maven using apt package manager with specific version
RUN apt-get update && \
    apt-get install -y maven=3.6.3-5 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the application source code and pom.xml
COPY . .

# Build the application using Maven
RUN mvn clean package -DskipTests

FROM eclipse-temurin:17-jdk-jammy
#Create empty jar file
RUN touch application.jar
#Copy generated jar and overwrite application.jar
COPY --from=builder /app/target/*.jar ./application.jar

# Expose the application port
EXPOSE 8080

# Define the command to run the Spring Boot application
CMD ["java", "-jar", "application.jar"]
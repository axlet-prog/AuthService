FROM maven:3.9.9 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package


FROM openjdk:23-jdk-slim
COPY --from=build /app/target/*.jar app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
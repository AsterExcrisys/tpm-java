# Image tpm-20-commons/tpm-java-builder
FROM gradle:8.5-jdk21 AS tpm-java-builder

ADD . /project
RUN cd /project && chmod +x ./gradlew && ./gradlew install

# Image tpm-20-commons/ttp
FROM eclipse-temurin:21 AS ttp

COPY --from=tpm-java-builder /project/ttp/build/install/ttp /project/ttp/ttp.sqlite /ttp/
RUN chmod +x /ttp/bin/ttp

EXPOSE 5001
WORKDIR /ttp
CMD ["./bin/ttp"]
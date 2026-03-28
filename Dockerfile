FROM cccs/assemblyline-v4-service-base:4.7.0.stable1

ENV SERVICE_PATH magpie.Magpie

USER root

# Install dependencies
# RUN pip install --no-cache-dir <your-dependencies>

USER assemblyline

WORKDIR /opt/al_service
COPY . .

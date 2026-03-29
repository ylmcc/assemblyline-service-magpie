FROM cccs/assemblyline-v4-service-base:4.7.0.stable1

ENV SERVICE_PATH magpie.Magpie

USER root

# Install dependencies
RUN pip install --no-cache-dir base58 bech32 requests

USER assemblyline

WORKDIR /opt/al_service
COPY . .

# Imagen de Jenkins con las herramientas que necesita el pipeline
FROM jenkins/jenkins:lts-jdk21
USER root
# Cliente Docker (sin motor): Jenkins usará el Docker de la máquina a través del socket
COPY --from=docker:cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker:cli /usr/local/libexec/docker/cli-plugins /usr/local/libexec/docker/cli-plugins
# Python para crear el entorno virtual y ejecutar Bandit / pip-audit / pruebas
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv python3-pip \
    && rm -rf /var/lib/apt/lists/*
# Plugins que usará el pipeline
RUN jenkins-plugin-cli --plugins git github workflow-aggregator pipeline-stage-view \
    htmlpublisher ws-cleanup credentials-binding timestamper
USER jenkins

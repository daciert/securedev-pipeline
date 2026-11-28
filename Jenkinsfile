// Pipeline DevSecOps de SecureDev: construcción → análisis → pruebas → despliegue
pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    // Integración continua: revisa el repositorio cada ~5 minutos y ejecuta si hay commits nuevos
    triggers { pollSCM('H/5 * * * *') }

    environment {
        IMAGE   = "securedev-app:${env.BUILD_NUMBER}"
        NET     = 'devsecops'
        STAGING = 'securedev-staging'   // entorno de pruebas (puerto 5001)
        PROD    = 'securedev-app'       // entorno de producción (puerto 5000)
    }

    stages {
        stage('Trazabilidad') {
            steps {
                sh '''
                    mkdir -p reports
                    {
                      echo "build:   #${BUILD_NUMBER}"
                      echo "fecha:   $(date -Iseconds)"
                      echo "rama:    ${GIT_BRANCH}"
                      echo "commit:  $(git rev-parse HEAD)"
                      git log -1 --pretty="autor:   %an <%ae>%nmensaje: %s"
                      echo "imagen:  ${IMAGE}"
                    } | tee reports/trazabilidad.txt
                '''
            }
        }

        stage('Construcción') {
            steps {
                sh '''
                    python3 -m venv .venv
                    .venv/bin/pip install --quiet --upgrade pip
                    .venv/bin/pip install --quiet -r requirements.txt -r requirements-dev.txt
                    docker build -t ${IMAGE} -t securedev-app:latest .
                '''
            }
        }

        stage('SAST - Bandit') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        .venv/bin/bandit -q -r app -f html -o reports/bandit.html --exit-zero
                        rc=0
                        .venv/bin/bandit -q -r app -ll -f txt -o reports/bandit.txt || rc=$?
                        cat reports/bandit.txt
                        exit $rc
                    '''
                }
            }
        }

        stage('SCA - pip-audit') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        .venv/bin/pip-audit -r requirements.txt --no-deps --desc -f markdown -o reports/pip-audit.md || true
                        rc=0
                        .venv/bin/pip-audit -r requirements.txt --no-deps -f columns || rc=$?
                        exit $rc
                    '''
                }
            }
        }

        stage('Pruebas') {
            steps {
                sh '''
                    .venv/bin/pytest tests/test_funcional.py -v -p no:warnings --junitxml=reports/junit-funcional.xml
                '''
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        .venv/bin/pytest tests/test_seguridad.py -v -p no:warnings --tb=line --junitxml=reports/junit-seguridad.xml
                    '''
                }
            }
            post { always { junit allowEmptyResults: true, testResults: 'reports/junit-*.xml' } }
        }

        stage('Despliegue (staging)') {
            steps {
                // Secretos desde las credenciales de Jenkins (nunca en el repositorio)
                withCredentials([string(credentialsId: 'securedev-admin-pass', variable: 'ADMIN_PASSWORD'),
                                 string(credentialsId: 'securedev-alumno-pass', variable: 'ALUMNO_PASSWORD')]) {
                    sh '''
                        export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
                        docker rm -f ${STAGING} >/dev/null 2>&1 || true
                        docker run -d --name ${STAGING} --network ${NET} -p 5001:5000 \
                            -e ADMIN_PASSWORD -e ALUMNO_PASSWORD -e SECRET_KEY ${IMAGE}
                        for i in $(seq 1 30); do
                            curl -fs -o /dev/null http://${STAGING}:5000/login && echo "Staging disponible" && exit 0
                            sleep 2
                        done
                        docker logs ${STAGING}; exit 1
                    '''
                }
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        chmod 777 /zap/wrk
                        rm -f /zap/wrk/zap-report.*
                        cp zap/rules.tsv /zap/wrk/rules.tsv   # excepciones justificadas (falsos positivos)
                        rc=0
                        docker run --rm --network ${NET} -v zap-wrk:/zap/wrk:rw zaproxy/zap-stable \
                            zap-full-scan.py -t http://${STAGING}:5000 -m 2 -T 20 -c rules.tsv \
                            -r zap-report.html -J zap-report.json -w zap-report.md || rc=$?
                        cp /zap/wrk/zap-report.* reports/ 2>/dev/null || true
                        exit $rc
                    '''
                }
            }
        }

        stage('Security Gate') {
            steps {
                script {
                    if (currentBuild.currentResult != 'SUCCESS') {
                        error('Security Gate: existen hallazgos de seguridad. Se bloquea el despliegue a producción.')
                    }
                    echo 'Security Gate superado: sin hallazgos bloqueantes.'
                }
            }
        }

        stage('Despliegue (producción)') {
            steps {
                withCredentials([string(credentialsId: 'securedev-admin-pass', variable: 'ADMIN_PASSWORD'),
                                 string(credentialsId: 'securedev-alumno-pass', variable: 'ALUMNO_PASSWORD')]) {
                    sh '''
                        export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
                        docker rm -f ${PROD} >/dev/null 2>&1 || true
                        docker run -d --name ${PROD} --network ${NET} -p 5000:5000 --restart unless-stopped \
                            -e ADMIN_PASSWORD -e ALUMNO_PASSWORD -e SECRET_KEY ${IMAGE}
                        echo "Producción actualizada con ${IMAGE}"
                    '''
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
            publishHTML(target: [reportDir: 'reports', reportFiles: 'zap-report.html, bandit.html',
                                 reportName: 'Reportes de Seguridad', keepAll: true,
                                 alwaysLinkToLastBuild: true, allowMissing: true])
        }
        success { echo 'Pipeline OK: versión segura desplegada en producción.' }
        failure { echo 'Pipeline detenido: revisar reportes de seguridad.' }
    }
}

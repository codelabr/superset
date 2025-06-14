#!/usr/bin/env bash
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Add this to install mysqlclient
apt-get update
apt-get install -y pkg-config
apt-get install -y gcc

set -eo pipefail

REQUIREMENTS_LOCAL="/app/docker/requirements-local.txt"

# If Cypress run — overwrite the password for admin and export env variables
if [ "$CYPRESS_CONFIG" == "true" ]; then
    export SUPERSET_CONFIG=tests.integration_tests.superset_test_config
    export SUPERSET_TESTENV=true
    export SUPERSET__SQLALCHEMY_DATABASE_URI=postgresql+psycopg2://superset:superset@db:5432/superset
fi

#
# Make sure we have dev requirements installed
#
if [ -f "${REQUIREMENTS_LOCAL}" ]; then
    echo "Installing local overrides at ${REQUIREMENTS_LOCAL}"
    pip install --no-cache-dir -r "${REQUIREMENTS_LOCAL}"
else
    echo "Skipping local overrides"
fi

case "${1}" in
    worker)
        echo "Starting Celery worker..."
        # setting up only 2 workers by default to contain memory usage in dev environments
        celery --app=superset.tasks.celery_app:app worker -O fair -l INFO --concurrency=${CELERYD_CONCURRENCY:-2}
        ;;
    beat)
        echo "Starting Celery beat..."
        rm -f /tmp/celerybeat.pid
        celery --app=superset.tasks.celery_app:app beat --pidfile /tmp/celerybeat.pid -l INFO -s "${SUPERSET_HOME}"/celerybeat-schedule
        ;;
    app)
        echo "Starting web app (using development server)..."
        flask run -p 8088 --with-threads --reload --debugger --host=0.0.0.0
        ;;
    app-gunicorn)
        echo "Starting web app..."
        /usr/bin/run-server.sh
        ;;
    *)
        echo "Unknown Operation!!!"
        ;;
esac

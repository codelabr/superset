# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# This file is included in the final Docker image and SHOULD be overridden when
# deploying the image to prod. Settings configured here are intended for use in local
# development environments. Also note that superset_config_docker.py is imported
# as a final step as a means to override "defaults" configured here
#

from keycloak_security_manager import OIDCSecurityManager
from flask_appbuilder.security.manager import AUTH_OID, AUTH_REMOTE_USER, AUTH_DB, AUTH_LDAP, AUTH_OAUTH
from flask_oidc import OpenIDConnect

import logging
import os

from celery.schedules import crontab
from flask_caching.backends.filesystemcache import FileSystemCache
import logging
logging.warning("==> LOADED CUSTOM superset_config.py")
# Define constants
# Superset chạy lang nghe trên tat ca IP o cong 8088
SUPERSET_WEBSERVER_ADDRESS = '0.0.0.0'
SUPERSET_WEBSERVER_PORT = 8088

# Ưu tiên sử dụng HTTPS trong các redirect / OAuth
PREFERRED_URL_SCHEME = "https"

# URL Keycloak cho xác thực
KEYCLOAK_BASE_URL = "https://sso.lagroup.vn/auth/realms/LinhAnh"

# URL công khai cua Superset qua reverse proxy (dùng domain thật)
#SUPERSET_BASE_URL = "http://172.24.180.14:8088"
SUPERSET_BASE_URL = "https://uatsuperset.lagroup.vn"

# Bật middleware xu ly header từ reverse proxy (Nginx)
#ENABLE_PROXY_FIX = True
#PROXY_FIX_CONFIG = {
#    'x_for': 1,
#    'x_proto': 1,
#    'x_host': 1,
#    'x_port': 1,
#    'x_prefix': 1,
#}
#SUPERSET_BASE_URL = "http://203.29.17.230:8088"
#SUPERSET_BASE_URL = "http://uatsuperset.lagroup.vn"
# Client ID and secret can be obtained in Keycloak
KEYCLOAK_CLIENT_ID = "superset-client"
KEYCLOAK_CLIENT_SECRET = "2svxzfervBQuWsuFovuG6kJdWNg6LtS4";

os.environ['REQUESTS_CA_BUNDLE'] = '/etc/ssl/certs/lagroup_vn.pem'

logger = logging.getLogger()

DATABASE_DIALECT = os.getenv("DATABASE_DIALECT")
DATABASE_USER = os.getenv("DATABASE_USER")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
DATABASE_HOST = os.getenv("DATABASE_HOST")
DATABASE_PORT = os.getenv("DATABASE_PORT")
DATABASE_DB = os.getenv("DATABASE_DB")

EXAMPLES_USER = os.getenv("EXAMPLES_USER")
EXAMPLES_PASSWORD = os.getenv("EXAMPLES_PASSWORD")
EXAMPLES_HOST = os.getenv("EXAMPLES_HOST")
EXAMPLES_PORT = os.getenv("EXAMPLES_PORT")
EXAMPLES_DB = os.getenv("EXAMPLES_DB")

# The SQLAlchemy connection string.
SQLALCHEMY_DATABASE_URI = (
    f"{DATABASE_DIALECT}://"
    f"{DATABASE_USER}:{DATABASE_PASSWORD}@"
    f"{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_DB}"
)

SQLALCHEMY_EXAMPLES_URI = (
    f"{DATABASE_DIALECT}://"
    f"{EXAMPLES_USER}:{EXAMPLES_PASSWORD}@"
    f"{EXAMPLES_HOST}:{EXAMPLES_PORT}/{EXAMPLES_DB}"
)

# Database settings for better handling
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'connect_args': {
        'connect_timeout': 30,
    }
}

# Error handling
SUPERSET_WEBSERVER_TIMEOUT = 60
WTF_CSRF_ENABLED = True
WTF_CSRF_TIME_LIMIT = None

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_CELERY_DB = os.getenv("REDIS_CELERY_DB", "0")
REDIS_RESULTS_DB = os.getenv("REDIS_RESULTS_DB", "1")

RESULTS_BACKEND = FileSystemCache("/app/superset_home/sqllab")

CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_KEY_PREFIX": "superset_",
    "CACHE_REDIS_HOST": REDIS_HOST,
    "CACHE_REDIS_PORT": REDIS_PORT,
    "CACHE_REDIS_DB": REDIS_RESULTS_DB,
}
DATA_CACHE_CONFIG = CACHE_CONFIG


class CeleryConfig:
    broker_url = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_CELERY_DB}"
    imports = (
        "superset.sql_lab",
        "superset.tasks.scheduler",
        "superset.tasks.thumbnails",
        "superset.tasks.cache",
    )
    result_backend = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_RESULTS_DB}"
    worker_prefetch_multiplier = 1
    task_acks_late = False
    beat_schedule = {
        "reports.scheduler": {
            "task": "reports.scheduler",
            "schedule": crontab(minute="*", hour="*"),
        },
        "reports.prune_log": {
            "task": "reports.prune_log",
            "schedule": crontab(minute=10, hour=0),
        },
    }

CELERY_CONFIG = CeleryConfig
HTML_SANITIZATION = False
print(">>> HTML_SANITIZATION =", HTML_SANITIZATION)
FEATURE_FLAGS = {"ALERT_REPORTS": True}
ALERT_REPORTS_NOTIFICATION_DRY_RUN = True
#WEBDRIVER_BASEURL = "http://superset:8088/"  # When using docker compose baseurl should be http://superset_app:8088/
WEBDRIVER_BASEURL = "http://superset_app:8088/"
# The base URL for the email report hyperlinks.
WEBDRIVER_BASEURL_USER_FRIENDLY = WEBDRIVER_BASEURL
SQLLAB_CTAS_NO_LIMIT = True

# Keycloak
AUTH_TYPE = AUTH_OID
SECRET_KEY = os.getenv("SUPERSET_SECRET_KEY", "this_is_a_secret_key")
# Will allow user self registration, allowing to create Flask users from Authorized User
AUTH_USER_REGISTRATION = True
# The default user self registration role
AUTH_USER_REGISTRATION_ROLE = "Public"

OIDC_CLIENT_SECRETS = {
    "web": {
        "issuer": KEYCLOAK_BASE_URL,
        "auth_uri": f"{KEYCLOAK_BASE_URL}/protocol/openid-connect/auth",
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
        "redirect_uris": [
            f"{SUPERSET_BASE_URL}/oauth-authorized/web",
        ],
        "userinfo_uri": f"{KEYCLOAK_BASE_URL}/protocol/openid-connect/userinfo",
        "token_uri": f"{KEYCLOAK_BASE_URL}/protocol/openid-connect/token",
        "token_introspection_uri": f"{KEYCLOAK_BASE_URL}/protocol/openid-connect/token/introspect",
        "logout_uri": f"{KEYCLOAK_BASE_URL}/protocol/openid-connect/logout"
    }
}

OIDC_ID_TOKEN_COOKIE_SECURE = True
OIDC_SCOPES = ["openid", "email", "profile", "roles"] 
OIDC_INTROSPECTION_AUTH_METHOD = "client_secret_post"
OIDC_OPENID_REALM = "LinhAnh"

# Add this to tell Keycloak where to redirect after logging out
OIDC_POST_LOGOUT_REDIRECT_URI = SUPERSET_BASE_URL + "/login"

# Role mapping from Keycloak to Superset
AUTH_ROLES_MAPPING = {
    "superset-admin": ["Admin"],
    "superset-alpha": ["Alpha"],
    "superset-gamma": ["Gamma"],
}

AUTH_ROLES_SYNC_AT_LOGIN = True

# Initialize OIDC
oidc = OpenIDConnect()

def init_app(app):
    oidc.init_app(app)

CUSTOM_SECURITY_MANAGER = OIDCSecurityManager

#
# Optionally import superset_config_docker.py (which will have been included on
# the PYTHONPATH) in order to allow for local settings to be overridden
#
try:
    import superset_config_docker
    from superset_config_docker import *  # noqa

    logger.info(
        f"Loaded your Docker configuration at " f"[{superset_config_docker.__file__}]"
    )
except ImportError:
    logger.info("Using default Docker config...")


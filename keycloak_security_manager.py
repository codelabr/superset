from flask_appbuilder.security.manager import AUTH_OID
from superset.security import SupersetSecurityManager
from flask_oidc import OpenIDConnect
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user, logout_user
from urllib.parse import quote
from flask_appbuilder.views import ModelView, SimpleFormView, expose
from flask import (
    redirect,
    request,
    session,
    Response
)
import logging
import jwt

class OIDCSecurityManager(SupersetSecurityManager):
    def __init__(self, appbuilder):
        super(OIDCSecurityManager, self).__init__(appbuilder)
        if self.auth_type == AUTH_OID:
            self.oid = OpenIDConnect(self.appbuilder.get_app)
            self.authoidview = AuthOIDCView

class AuthOIDCView(AuthOIDView):
    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):
        sm = self.appbuilder.sm
        oidc = sm.oid
        logger = logging.getLogger(__name__)

        @self.appbuilder.sm.oid.require_login
        def handle_login():
            logger.info("Entering login handler")
            user = sm.auth_user_oid(oidc.user_getfield('email'))
            info = oidc.user_getinfo(['preferred_username', 'given_name', 'family_name', 'email'])
            token = oidc.get_access_token()  # Lấy access_token

            try:
                # Decode không verify (vì đã được oidc xác thực)
                payload = jwt.decode(token, options={"verify_signature": False})
                roles = payload.get('realm_access', {}).get('roles', [])
                logger.info(f"Extracted roles from token: {roles}")
            except Exception as e:
                logger.error(f"Failed to decode token: {e}")
                roles = []

            if user is None:
                username = info.get('preferred_username')
                first_name = info.get('given_name')
                last_name = info.get('family_name')
                email = info.get('email')
                mapped_role = sm.find_role('Gamma')

                for keycloak_role, superset_roles in sm.appbuilder.get_app.config['AUTH_ROLES_MAPPING'].items():
                    if keycloak_role in roles:
                        mapped_role = sm.find_role(superset_roles[0])
                        break

                logger.info(f"Mapping role for {username}: Keycloak role {keycloak_role} -> Superset role {mapped_role.name}")
                user = sm.add_user(username, first_name, last_name, email, mapped_role)
            else:
                mapped_role = sm.find_role('Gamma')
                for keycloak_role, superset_roles in sm.appbuilder.get_app.config['AUTH_ROLES_MAPPING'].items():
                    if keycloak_role in roles:
                        mapped_role = sm.find_role(superset_roles[0])
                        break

                if user.roles[0].name != mapped_role.name:
                    user.roles = [mapped_role]
                    sm.update_user(user)
                    logger.info(f"Updated role for {user.username}: New role {mapped_role.name}")

            login_user(user, remember=False)
            logger.info(f"Logged in user: {user.username} with role: {user.roles[0].name}")
            return redirect(self.appbuilder.get_url_for_index)

        return handle_login()

    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):
        oidc = self.appbuilder.sm.oid
        logger = logging.getLogger(__name__)

        # Hủy phiên Superset (xóa cookie phiên của Flask)
        session.clear()
        logger.info("Session cleared in logout function")

        # Hủy trạng thái đăng nhập của Flask-Login (đảm bảo user không còn được coi là đã đăng nhập)
        logout_user()
        logger.info("User logged out via Flask-Login")

        # Gọi logout của Flask-AppBuilder
        super(AuthOIDCView, self).logout()
        logger.info("Flask-AppBuilder logout called")

        # Gọi logout của Keycloak (hủy phiên Keycloak)
        oidc.logout()
        logger.info("Keycloak logout called")

        # Lấy logout_uri từ cấu hình
        logout_uri = oidc.client_secrets.get('logout_uri')
        logger.info(f"Logout URI: {logout_uri}")

        # Lấy post_logout_redirect_uri từ cấu hình
        redirect_url = self.appbuilder.app.config.get("OIDC_POST_LOGOUT_REDIRECT_URI",
                                                     request.url_root.strip('/') + self.appbuilder.get_url_for_login)
        logger.info(f"Post logout redirect URL: {redirect_url}")

        # Xóa cookie session của Superset
        response = Response()
        response.delete_cookie('session', path='/')
        logger.info("Session cookie deleted")

        response.headers['Location'] = f"{logout_uri}?post_logout_redirect_uri={quote(redirect_url)}"
        response.status_code = 302
        logger.info(f"Redirecting to: {response.headers['Location']}")

        return response

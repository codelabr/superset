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
            
            # Get user info from OIDC
            info = oidc.user_getinfo(['preferred_username', 'given_name', 'family_name', 'email'])
            token = oidc.get_access_token()
            
            # Extract user details
            username = info.get('preferred_username')
            first_name = info.get('given_name')
            last_name = info.get('family_name')
            email = info.get('email')
            
            logger.info(f"Processing login for user: {username}, email: {email}")
            
            # Decode token to get roles
            try:
                payload = jwt.decode(token, options={"verify_signature": False})
                roles = payload.get('realm_access', {}).get('roles', [])
                logger.info(f"Extracted roles from token: {roles}")
            except Exception as e:
                logger.error(f"Failed to decode token: {e}")
                roles = []

            # Determine the mapped role
            mapped_role = sm.find_role('Gamma')  # Default role
            for keycloak_role, superset_roles in sm.appbuilder.get_app.config['AUTH_ROLES_MAPPING'].items():
                if keycloak_role in roles:
                    mapped_role = sm.find_role(superset_roles[0])
                    logger.info(f"Mapping role for {username}: Keycloak role {keycloak_role} -> Superset role {mapped_role.name}")
                    break

            # Try to find existing user first by email (more reliable than username)
            user = sm.find_user(email=email)
            
            if user is None:
                # Try to find by username as fallback
                user = sm.find_user(username=username)
            
            if user is None:
                # Create new user
                logger.info(f"Creating new user: {username}")
                try:
                    user = sm.add_user(
                        username=username,
                        first_name=first_name,
                        last_name=last_name,
                        email=email,
                        role=mapped_role
                    )
                    if user:
                        logger.info(f"Successfully created user: {username} with role: {mapped_role.name}")
                    else:
                        logger.error(f"Failed to create user: {username}")
                        return redirect(self.appbuilder.get_url_for_login + "?error=user_creation_failed")
                except Exception as e:
                    logger.error(f"Error creating user {username}: {e}")
                    # Try to find the user again in case it was created by another process
                    user = sm.find_user(email=email) or sm.find_user(username=username)
                    if user is None:
                        return redirect(self.appbuilder.get_url_for_login + "?error=user_creation_failed")
            else:
                # Update existing user's role if needed
                logger.info(f"Found existing user: {username}")
                try:
                    # Ensure user has the correct role
                    if not user.roles or user.roles[0].name != mapped_role.name:
                        user.roles = [mapped_role]
                        sm.update_user(user)
                        logger.info(f"Updated role for {user.username}: New role {mapped_role.name}")
                    
                    # Update user info if needed
                    if (user.first_name != first_name or 
                        user.last_name != last_name or 
                        user.email != email):
                        user.first_name = first_name
                        user.last_name = last_name
                        user.email = email
                        sm.update_user(user)
                        logger.info(f"Updated user info for {user.username}")
                        
                except Exception as e:
                    logger.error(f"Error updating user {username}: {e}")

            # Verify we have a valid user object
            if user is None:
                logger.error("User object is None after creation/retrieval")
                return redirect(self.appbuilder.get_url_for_login + "?error=invalid_user")
            
            # Check if user is active (handle both boolean and object cases)
            try:
                if hasattr(user, 'is_active'):
                    if not user.is_active:
                        logger.warning(f"User {user.username} is not active")
                        return redirect(self.appbuilder.get_url_for_login + "?error=user_inactive")
                else:
                    logger.warning(f"User object does not have is_active attribute: {type(user)}")
            except Exception as e:
                logger.error(f"Error checking user active status: {e}")

            # Log in the user
            try:
                login_user(user, remember=False)
                logger.info(f"Successfully logged in user: {user.username} with role: {user.roles[0].name if user.roles else 'No role'}")
                return redirect(self.appbuilder.get_url_for_index)
            except Exception as e:
                logger.error(f"Error during login_user: {e}")
                return redirect(self.appbuilder.get_url_for_login + "?error=login_failed")

        return handle_login()
    
    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):
        oidc = self.appbuilder.sm.oid
        logger = logging.getLogger(__name__)

        # Clear Superset session
        session.clear()
        logger.info("Session cleared in logout function")
        
        # Logout from Flask-Login
        logout_user()
        logger.info("User logged out via Flask-Login")
        
        # Call Flask-AppBuilder logout
        super(AuthOIDCView, self).logout()
        logger.info("Flask-AppBuilder logout called")
        
        # Logout from Keycloak
        oidc.logout()
        logger.info("Keycloak logout called")
        
        # Get logout URI from configuration
        logout_uri = oidc.client_secrets.get('logout_uri')
        logger.info(f"Logout URI: {logout_uri}")
        
        # Get post logout redirect URI
        redirect_url = self.appbuilder.app.config.get("OIDC_POST_LOGOUT_REDIRECT_URI", 
                                                      request.url_root.strip('/') + self.appbuilder.get_url_for_login)
        logger.info(f"Post logout redirect URL: {redirect_url}")

        # Delete session cookie
        response = Response()
        response.delete_cookie('session', path='/')
        logger.info("Session cookie deleted")
        response.headers['Location'] = f"{logout_uri}?post_logout_redirect_uri={quote(redirect_url)}"
        response.status_code = 302
        logger.info(f"Redirecting to: {response.headers['Location']}")
        return response

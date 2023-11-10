package willydekeyser.config;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Base64;
import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;


public final class MyOidcLogoutAuthenticationProvider implements AuthenticationProvider {
	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE =
			new OAuth2TokenType(OidcParameterNames.ID_TOKEN);
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;
	private final SessionRegistry sessionRegistry;

	public MyOidcLogoutAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService, SessionRegistry sessionRegistry) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.sessionRegistry = sessionRegistry;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OidcLogoutAuthenticationToken oidcLogoutAuthentication =
				(OidcLogoutAuthenticationToken) authentication;

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				oidcLogoutAuthentication.getIdTokenHint(), ID_TOKEN_TOKEN_TYPE);
		System.err.println(authorization);
		if (authorization == null) {
			throwError(OAuth2ErrorCodes.INVALID_TOKEN, "id_token_hint");
		}

		OAuth2Authorization.Token<OidcIdToken> authorizedIdToken = authorization.getToken(OidcIdToken.class);
		if (!authorizedIdToken.isActive()) {
			System.err.println(authorizedIdToken.isActive());
			//throwError(OAuth2ErrorCodes.INVALID_TOKEN, "id_token_hint");
		}

		RegisteredClient registeredClient = this.registeredClientRepository.findById(
				authorization.getRegisteredClientId());

		OidcIdToken idToken = authorizedIdToken.getToken();

		List<String> audClaim = idToken.getAudience();
		if (CollectionUtils.isEmpty(audClaim) ||
				!audClaim.contains(registeredClient.getClientId())) {
			throwError(OAuth2ErrorCodes.INVALID_TOKEN, IdTokenClaimNames.AUD);
		}
		if (StringUtils.hasText(oidcLogoutAuthentication.getClientId()) &&
				!oidcLogoutAuthentication.getClientId().equals(registeredClient.getClientId())) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
		}
		if (StringUtils.hasText(oidcLogoutAuthentication.getPostLogoutRedirectUri()) &&
				!registeredClient.getPostLogoutRedirectUris().contains(oidcLogoutAuthentication.getPostLogoutRedirectUri())) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, "post_logout_redirect_uri");
		}

		if (oidcLogoutAuthentication.isPrincipalAuthenticated()) {
			Authentication currentUserPrincipal = (Authentication) oidcLogoutAuthentication.getPrincipal();
			Authentication authorizedUserPrincipal = authorization.getAttribute(Principal.class.getName());
			if (!StringUtils.hasText(idToken.getSubject()) ||
					!currentUserPrincipal.getName().equals(authorizedUserPrincipal.getName())) {
				throwError(OAuth2ErrorCodes.INVALID_TOKEN, IdTokenClaimNames.SUB);
			}

			if (StringUtils.hasText(oidcLogoutAuthentication.getSessionId())) {
				SessionInformation sessionInformation = findSessionInformation(
						currentUserPrincipal, oidcLogoutAuthentication.getSessionId());
				if (sessionInformation != null) {
					String sessionIdHash;
					try {
						sessionIdHash = createHash(sessionInformation.getSessionId());
					} catch (NoSuchAlgorithmException ex) {
						OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
								"Failed to compute hash for Session ID.", null);
						throw new OAuth2AuthenticationException(error);
					}

					String sidClaim = idToken.getClaim("sid");
					if (!StringUtils.hasText(sidClaim) ||
							!sidClaim.equals(sessionIdHash)) {
						throwError(OAuth2ErrorCodes.INVALID_TOKEN, "sid");
					}
				}
			}
		}

		return new OidcLogoutAuthenticationToken(idToken, (Authentication) oidcLogoutAuthentication.getPrincipal(),
				oidcLogoutAuthentication.getSessionId(), oidcLogoutAuthentication.getClientId(),
				oidcLogoutAuthentication.getPostLogoutRedirectUri(), oidcLogoutAuthentication.getState());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OidcLogoutAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private SessionInformation findSessionInformation(Authentication principal, String sessionId) {
		List<SessionInformation> sessions = this.sessionRegistry.getAllSessions(principal.getPrincipal(), true);
		SessionInformation sessionInformation = null;
		if (!CollectionUtils.isEmpty(sessions)) {
			for (SessionInformation session : sessions) {
				if (session.getSessionId().equals(sessionId)) {
					sessionInformation = session;
					break;
				}
			}
		}
		return sessionInformation;
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(
				errorCode,
				"OpenID Connect 1.0 Logout Request Parameter: " + parameterName,
				"https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling");
		throw new OAuth2AuthenticationException(error);
	}

	private static String createHash(String value) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}
}

package willydekeyser.config;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

public class MyOAuth2RefreshTokenAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
	private final OAuth2AuthorizationService authorizationService;
	private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

	public MyOAuth2RefreshTokenAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		this.authorizationService = authorizationService;
		this.tokenGenerator = tokenGenerator;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
		System.err.println("MyOAuth2RefreshTokenAuthenticationProvider: " + authentication.getName());
		
		OAuth2RefreshTokenAuthenticationToken refreshTokenAuthentication =
				(OAuth2RefreshTokenAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal =
				OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient(refreshTokenAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				refreshTokenAuthentication.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		}

		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
		if (!refreshToken.isActive()) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		Set<String> scopes = refreshTokenAuthentication.getScopes();
		Set<String> authorizedScopes = authorization.getAuthorizedScopes();
		if (!authorizedScopes.containsAll(scopes)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
		}

		if (scopes.isEmpty()) {
			scopes = authorizedScopes;
		}

		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(authorization.getAttribute(Principal.class.getName()))
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorization(authorization)
				.authorizedScopes(scopes)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrant(refreshTokenAuthentication);

		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);

		// ----- Access token -----
		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
		if (generatedAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the access token.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
				generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
		if (generatedAccessToken instanceof ClaimAccessor) {
			authorizationBuilder.token(accessToken, (metadata) -> {
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims());
				metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
			});
		} else {
			authorizationBuilder.accessToken(accessToken);
		}

		// ----- Refresh token -----
		OAuth2RefreshToken currentRefreshToken = refreshToken.getToken();
		if (!registeredClient.getTokenSettings().isReuseRefreshTokens()) {
			tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
			OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
			if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
						"The token generator failed to generate the refresh token.", ERROR_URI);
				throw new OAuth2AuthenticationException(error);
			}

			currentRefreshToken = (OAuth2RefreshToken) generatedRefreshToken;
			authorizationBuilder.refreshToken(currentRefreshToken);
		}

		authorization = authorizationBuilder.build();

		this.authorizationService.save(authorization);
		Map<String, Object> additionalParameters = Collections.emptyMap();
		return new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken, currentRefreshToken, additionalParameters);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}
}

class OAuth2AuthenticationProviderUtils {

	static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
		OAuth2ClientAuthenticationToken clientPrincipal = null;
		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
		}
		if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
			return clientPrincipal;
		}
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	static <T extends OAuth2Token> OAuth2Authorization invalidate(
			OAuth2Authorization authorization, T token) {

		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
				.token(token,
						(metadata) ->
								metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

		if (OAuth2RefreshToken.class.isAssignableFrom(token.getClass())) {
			authorizationBuilder.token(
					authorization.getAccessToken().getToken(),
					(metadata) ->
							metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

			OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
					authorization.getToken(OAuth2AuthorizationCode.class);
			if (authorizationCode != null && !authorizationCode.isInvalidated()) {
				authorizationBuilder.token(
						authorizationCode.getToken(),
						(metadata) ->
								metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
			}
		}

		return authorizationBuilder.build();
	}
}

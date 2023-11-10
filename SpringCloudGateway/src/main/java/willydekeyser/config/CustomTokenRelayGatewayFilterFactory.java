package willydekeyser.config;

import static org.springframework.security.oauth2.core.web.reactive.function.OAuth2BodyExtractors.oauth2AccessTokenResponse;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.TokenRelayGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;


@Component
public class CustomTokenRelayGatewayFilterFactory extends TokenRelayGatewayFilterFactory {

    private static final String TOKEN_REFRESHMENT_ERROR_MESSAGE = "Stale session or token";
    private static final String GRANT_TYPE_KEY = "grant_type";
    private static final String REFRESH_TOKEN_KEY = "refresh_token";
    private static final Clock CLOCK = Clock.systemUTC();

    private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
    private final WebClient.Builder webClientBuilder;
    private final Duration accessTokenExpiresSkew = Duration.ofMinutes(10);
 
    public CustomTokenRelayGatewayFilterFactory(
    		ObjectProvider<ReactiveOAuth2AuthorizedClientManager> clientManagerProvider,
            final ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
            final WebClient.Builder webClientBuilder) {
        super(clientManagerProvider);
        this.authorizedClientRepository = authorizedClientRepository;
        this.webClientBuilder = webClientBuilder;
    }

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> exchange.getPrincipal()
                .filter(principal -> principal instanceof OAuth2AuthenticationToken)
                .cast(OAuth2AuthenticationToken.class)
                .flatMap(authentication -> getAuthorizedClient(exchange, authentication))
                .flatMap(authenticationPair -> {
                    if (shouldRefresh(authenticationPair.getOAuth2AuthorizedClient())) {
                        return refreshAuthorizedClient(exchange, authenticationPair.getOAuth2AuthorizedClient(), authenticationPair.getOAuth2AuthenticationToken());
                    } else {
                        return Mono.just(authenticationPair.getOAuth2AuthorizedClient());
                    }
                })
                .map(OAuth2AuthorizedClient::getAccessToken)
                .map(token -> withBearerAuth(exchange, token))
                .defaultIfEmpty(exchange).flatMap(chain::filter);
    }

    private Mono<AuthenticationPair> getAuthorizedClient(final ServerWebExchange exchange, final OAuth2AuthenticationToken oauth2Authentication) {
        return this.authorizedClientRepository.loadAuthorizedClient(
                oauth2Authentication.getAuthorizedClientRegistrationId(),
                oauth2Authentication,
                exchange)
                .map(oAuth2AuthorizedClient -> new AuthenticationPair(oAuth2AuthorizedClient, oauth2Authentication));
    }

    private static ServerWebExchange withBearerAuth(final ServerWebExchange exchange, final OAuth2AccessToken accessToken) {
        return exchange.mutate()
                .request(r -> r.headers(
                        headers -> headers.setBearerAuth(accessToken.getTokenValue())))
                .build();
    }

    private boolean shouldRefresh(final OAuth2AuthorizedClient authorizedClient) {
        final OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
        if (refreshToken == null) {
        	System.err.println("No refresh token available");
            return false;
        }
        final Instant now = CLOCK.instant();
        final Instant expiresAt = authorizedClient.getAccessToken().getExpiresAt();
        System.err.println(expiresAt + " - " + this.accessTokenExpiresSkew + " - " + now.isAfter(expiresAt.minus(this.accessTokenExpiresSkew)));
        if (now.isAfter(expiresAt.minus(this.accessTokenExpiresSkew))) {
        	System.err.println("Access token expired and should be refreshed");
            return true;
        }
        return false;
    }

    private Mono<OAuth2AuthorizedClient> refreshAuthorizedClient(
            final ServerWebExchange exchange,
            final OAuth2AuthorizedClient authorizedClient,
            final OAuth2AuthenticationToken oauth2Authentication) {
        final ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
        headers.add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        return webClientBuilder.build()
                .method(HttpMethod.POST)
                .uri(clientRegistration.getProviderDetails().getTokenUri())
                .headers(header -> header.addAll(headers))
                .bodyValue(refreshTokenBody(authorizedClient.getRefreshToken().getTokenValue()))
                .exchangeToMono(refreshResponse -> {
                	if (refreshResponse.statusCode().equals(HttpStatus.BAD_REQUEST)) {
                		System.err.println("The refresh token or sessions expired.");
                        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, TOKEN_REFRESHMENT_ERROR_MESSAGE);
                	} else {
                		return refreshResponse.body(oauth2AccessTokenResponse());
                	}
                })
                .map(accessTokenResponse -> {
                    OAuth2RefreshToken refreshToken = Optional.ofNullable(accessTokenResponse.getRefreshToken())
                            .orElse(authorizedClient.getRefreshToken());                       
                    return new OAuth2AuthorizedClient(authorizedClient.getClientRegistration(), 
                    		authorizedClient.getPrincipalName(), 
                    		accessTokenResponse.getAccessToken(), 
                    		//authorizedClient.getRefreshToken()); 
                    		refreshToken);
                })
                .flatMap(result -> this.authorizedClientRepository.saveAuthorizedClient(result, oauth2Authentication, exchange).thenReturn(result));
    }

    private static MultiValueMap<String, String> refreshTokenBody(final String refreshToken) {
        final MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add(GRANT_TYPE_KEY, AuthorizationGrantType.REFRESH_TOKEN.getValue());
        body.add(REFRESH_TOKEN_KEY, refreshToken);
        return body;
    }

    private static class AuthenticationPair {

    	private final OAuth2AuthorizedClient oAuth2AuthorizedClient;
        private final OAuth2AuthenticationToken oAuth2AuthenticationToken;
        
		public AuthenticationPair(OAuth2AuthorizedClient oAuth2AuthorizedClient,
				OAuth2AuthenticationToken oAuth2AuthenticationToken) {
			this.oAuth2AuthorizedClient = oAuth2AuthorizedClient;
			this.oAuth2AuthenticationToken = oAuth2AuthenticationToken;
		}

        public OAuth2AuthorizedClient getOAuth2AuthorizedClient() {
			return oAuth2AuthorizedClient;
		}

		public OAuth2AuthenticationToken getOAuth2AuthenticationToken() {
			return oAuth2AuthenticationToken;
		}
    }
}
package willydekeyser.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestHandler;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.web.server.WebFilter;

import reactor.core.publisher.Mono;

@Configuration
@EnableReactiveMethodSecurity
public class SecurityConfig {

	private final ReactiveClientRegistrationRepository reactiveClientRegistrationRepository;
	
	public SecurityConfig(ReactiveClientRegistrationRepository reactiveClientRegistrationRepository) {
		this.reactiveClientRegistrationRepository = reactiveClientRegistrationRepository;
	}
	
	@Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http, 
    		ServerOAuth2AuthorizationRequestResolver resolver) {
		CookieServerCsrfTokenRepository tokenRepository = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
	    tokenRepository.setCookiePath("/");
	    tokenRepository.setHeaderName("X-XSRF-TOKEN");
	    XorServerCsrfTokenRequestAttributeHandler delegate = new XorServerCsrfTokenRequestAttributeHandler();
	    ServerCsrfTokenRequestHandler requestHandler = delegate::handle;
		return http
                .authorizeExchange(exchange -> exchange
                		.pathMatchers("/**").permitAll()
                		.anyExchange().authenticated())
                .logout(logout -> logout
                		.logoutUrl("/logout")
                		.logoutSuccessHandler(serverLogoutSuccessHandler(reactiveClientRegistrationRepository)))
                		//.logoutSuccessHandler(new AngularLogoutSucessHandler(reactiveClientRegistrationRepository, "http://127.0.0.1:8090")))
                .cors(withDefaults())
                .csrf(csrf -> csrf
                		.csrfTokenRepository(tokenRepository)
            			.csrfTokenRequestHandler(requestHandler)
                		)
                .oauth2Login(auth -> auth
                		.authorizationRequestResolver(resolver))
                .oauth2Client(withDefaults())
                .build();
    }
		
	@Bean
	WebFilter csrfCookieWebFilter() {
		return (exchange, chain) -> {
			Mono<CsrfToken> csrfToken = exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
			return csrfToken.doOnSuccess(token -> {
			}).then(chain.filter(exchange));
		};
	}
	
	@Bean
	ServerLogoutSuccessHandler serverLogoutSuccessHandler(ReactiveClientRegistrationRepository repository) {
	       OidcClientInitiatedServerLogoutSuccessHandler oidcLogoutSuccessHandler = new OidcClientInitiatedServerLogoutSuccessHandler(repository);
	       oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/");
	       return oidcLogoutSuccessHandler;
	}
	
	@Bean
	ServerOAuth2AuthorizationRequestResolver pkceResolver(ReactiveClientRegistrationRepository repo) {
	    var resolver = new DefaultServerOAuth2AuthorizationRequestResolver(repo);
	    resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
	    return resolver;
	}
	
	static class AngularLogoutSucessHandler implements ServerLogoutSuccessHandler {
		private final OidcClientInitiatedServerLogoutSuccessHandler delegate;
		
		public AngularLogoutSucessHandler(ReactiveClientRegistrationRepository clientRegistrationRepository, String postLogoutRedirectUri) {
			this.delegate = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
			this.delegate.setPostLogoutRedirectUri(postLogoutRedirectUri);
		}

		@Override
		public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
			return delegate.onLogoutSuccess(exchange, authentication).then(Mono.fromRunnable(() -> {
				exchange.getExchange().getResponse().setStatusCode(HttpStatus.ACCEPTED);
			}));
		}

	}

}
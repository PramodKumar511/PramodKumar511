package com.scriptulate.pdmp.engine.security;

import static org.springframework.security.oauth2.core.web.reactive.function.OAuth2BodyExtractors.oauth2AccessTokenResponse;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.ClientCredentialsReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.server.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;

import com.scriptulate.model.UserBase;
import com.scriptulate.pdmp.engine.user.ScriptulateOAuth2User;
import com.scriptulate.respository.DoctorRepository;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;


@Configuration
@Slf4j
@EnableReactiveMethodSecurity
public class APISecurityConfigurer{
	
	@Value("${allowed.origin}")
	private String allowedOrigin;
	
	@Value("${auth0.baseURI}")
	private String baseURI;
	
	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,SriptulateReactiveAuthenticationManager reactiveAuthenticationManager) {
	 
	   http.oauth2ResourceServer()
	   			.bearerTokenConverter(new ServerAuthenticationConverter() {
	   				private ServerBearerTokenAuthenticationConverter serverBearerTokenAuthenticationConverter 
	   																= new ServerBearerTokenAuthenticationConverter();
					@Override
					public Mono<Authentication> convert(ServerWebExchange exchange) {
						Mono<Authentication> bearerToken = serverBearerTokenAuthenticationConverter.convert(exchange);
						return bearerToken.map(bearerTokenAuth->{
							return new IdTokenAuthentication(bearerTokenAuth.getPrincipal().toString(), 
									exchange.getRequest().getHeaders().getFirst("id_token"));
						});
					}
				})
	   			.authenticationManagerResolver(new ReactiveAuthenticationManagerResolver<ServerHttpRequest>() {
					@Override
					public Mono<ReactiveAuthenticationManager> resolve(ServerHttpRequest context) {
						return Mono.just(reactiveAuthenticationManager);
					}
				}).and().cors().configurationSource(new CorsConfigurationSource() {
					@Override
					public CorsConfiguration getCorsConfiguration(ServerWebExchange exchange) {
						final CorsConfiguration config = new CorsConfiguration();
						Arrays.stream(allowedOrigin.split(",")).map(String::trim).forEach(config::addAllowedOrigin);
						config.addAllowedMethod(HttpMethod.POST);
						config.addAllowedMethod(HttpMethod.GET);
						config.addAllowedHeader("*");
						return config;
					}
				})
	   			.and().authorizeExchange()
	   			.pathMatchers(HttpMethod.GET,"/patient/account/**").hasAnyAuthority("Physician")
	   			.pathMatchers(HttpMethod.POST,"/task/**").hasAnyAuthority("Physician")
	   			.pathMatchers(HttpMethod.GET,"/task/**").hasAnyAuthority("Physician","Patient")
	   			.pathMatchers(HttpMethod.GET,"/report/**").hasAnyAuthority("Physician")
	            .pathMatchers(HttpMethod.POST,"/report/**").hasAnyAuthority("Physician")
	            .pathMatchers(HttpMethod.POST,"/element/**").hasAnyAuthority("Physician")
	            .pathMatchers(HttpMethod.GET,"/element/**").hasAnyAuthority("Physician")
	            .pathMatchers(HttpMethod.GET, "/internal/healthz").permitAll();
	   return http.build();
	}
	
	public static final class IdTokenAuthentication extends BearerTokenAuthenticationToken {

		private String idToken;
		
		public IdTokenAuthentication(String accessToken, String idToken) {
			super(accessToken);
			this.idToken=idToken;
		}
		
		public String getIdToken() {
			return idToken;
		}
	
	}

	@Component
	public static class SriptulateReactiveAuthenticationManager implements ReactiveAuthenticationManager {

		@Autowired
		private DoctorRepository userRepository;
		
		private final NimbusJwtDecoder jwtDecoder;
		private final JwtDecoder jwtIdDecoder;

		public SriptulateReactiveAuthenticationManager(@Value("${oauth2.issuer}") String issuer,
				@Value("${oauth2.auth0.audience}") String audience) {
			String jwkSetUri =issuer+".well-known/jwks.json";
			this.jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
			OAuth2TokenValidator<Jwt> jwtValidator= jwtValidator(issuer,audience);
			jwtDecoder.setJwtValidator(jwtValidator);
			jwtIdDecoder = JwtDecoders.fromIssuerLocation(issuer);
		}

		private OAuth2TokenValidator<Jwt>  jwtValidator(String issuer, String audience) {
			List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
			    validators.add(new JwtTimestampValidator());
			    validators.add(new JwtIssuerValidator(issuer));
			    validators.add(token -> {
			        Set<String> expectedAudience =Arrays.stream(audience.split(",")).collect(Collectors.toSet());
			        return !Collections.disjoint(token.getAudience(), expectedAudience)
			            ? OAuth2TokenValidatorResult.success()
			            : OAuth2TokenValidatorResult.failure(new OAuth2Error(
			                OAuth2ErrorCodes.INVALID_REQUEST,
			                "This aud claim is not equal to the configured audience",
			                "https://tools.ietf.org/html/rfc6750#section-3.1"));
			    });
			    OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators);
			    return validator;
		}

		@Transactional
		@Override
		public Mono<Authentication> authenticate(Authentication authentication) {
			IdTokenAuthentication authenticationToken = (IdTokenAuthentication)authentication;
			String token = (String)authenticationToken.getPrincipal();
			Jwt accessTokenJWT = jwtDecoder.decode(token);
			Jwt idTokenJWT = jwtIdDecoder.decode(authenticationToken.getIdToken());
			log.debug("User Identifier {}",accessTokenJWT.getSubject());
			UserBase user = userRepository.findOneByExternalId(accessTokenJWT.getSubject());
			if(user==null) {
				throw new OAuth2AuthenticationException(new OAuth2Error("No User Found"));
			}
			Collection<GrantedAuthority> authorities = new ArrayList<>();
			for (String scope : user.getUserGroups().stream()
						.flatMap(f->f.getUserGroupRoles().stream())
						.map(f->f.getRole().getRole())
						.collect(Collectors.toList())) {
				authorities.add(new SimpleGrantedAuthority(scope));
			}
			OAuth2AccessToken accessToken = getConnectionAccessToken(accessTokenJWT);
			OidcIdToken idToken = getConnectionIdToken(idTokenJWT);
			ScriptulateOAuth2User scriptulateOAuth2User = 
							new ScriptulateOAuth2User(user, accessToken, 
													authorities, idToken, 
													new OidcUserInfo(accessTokenJWT.getClaims()), 
													IdTokenClaimNames.SUB, 
													user.getUserIdentifier().getSystem());
			OAuth2AuthenticationToken oAuth2AuthenticationToken = 
								new OAuth2AuthenticationToken(scriptulateOAuth2User, authorities, 
										user.getUserIdentifier().getSystem());
			oAuth2AuthenticationToken.setAuthenticated(true);
			return Mono.just(oAuth2AuthenticationToken);
		}
		
		private OAuth2AccessToken getConnectionAccessToken(Jwt jwt) {
			return new OAuth2AccessToken(TokenType.BEARER, jwt.getTokenValue(), jwt.getIssuedAt(),jwt.getExpiresAt());
		}
		
		private OidcIdToken getConnectionIdToken(Jwt jwt) {
			return new OidcIdToken(jwt.getTokenValue(), jwt.getIssuedAt(),jwt.getExpiresAt(),jwt.getClaims());
		}
	}
	
	@Bean
	WebClient webClient(ReactiveClientRegistrationRepository clientRegistrations) {
		InMemoryReactiveOAuth2AuthorizedClientService clientService = new InMemoryReactiveOAuth2AuthorizedClientService(clientRegistrations);
		ServerOAuth2AuthorizedClientRepository authorizedClients = new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(clientService);
		DefaultReactiveOAuth2AuthorizedClientManager authorizedClientManager = new DefaultReactiveOAuth2AuthorizedClientManager(clientRegistrations, authorizedClients);
		ClientCredentialsReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = new ClientCredentialsReactiveOAuth2AuthorizedClientProvider();
		authorizedClientProvider.setAccessTokenResponseClient(new ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest>() {
			
			private WebClient webClient = WebClient.builder()
					.build();

			@Override
			public Mono<OAuth2AccessTokenResponse> getTokenResponse(OAuth2ClientCredentialsGrantRequest authorizationGrantRequest) {
				return Mono.defer(() -> {
					ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();

					String tokenUri = clientRegistration.getProviderDetails().getTokenUri();
					BodyInserters.FormInserter<String> body = body(authorizationGrantRequest);

					return this.webClient.post()
							.uri(tokenUri)
							.accept(MediaType.APPLICATION_JSON)
							.headers(headers(clientRegistration))
							.body(body)
							.exchange()
							.flatMap(response -> {
								HttpStatus status = HttpStatus.resolve(response.rawStatusCode());
								if (status == null || !status.is2xxSuccessful()) {
									// extract the contents of this into a method named oauth2AccessTokenResponse but has an argument for the response
									return response.bodyToFlux(DataBuffer.class)
										.map(DataBufferUtils::release)
										.then(Mono.error(WebClientResponseException.create(response.rawStatusCode(),
													"Cannot get token, expected 2xx HTTP Status code",
													null,
													null,
													null
										)));
								}
								return response.body(oauth2AccessTokenResponse()); })
							.map(response -> {
								if (response.getAccessToken().getScopes().isEmpty()) {
									response = OAuth2AccessTokenResponse.withResponse(response)
										.scopes(authorizationGrantRequest.getClientRegistration().getScopes())
										.build();
								}
								return response;
							});
				});
			}

			private Consumer<HttpHeaders> headers(ClientRegistration clientRegistration) {
				return headers -> {
					headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
					if (ClientAuthenticationMethod.BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
						headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
					}
				};
			}

			private BodyInserters.FormInserter<String> body(OAuth2ClientCredentialsGrantRequest authorizationGrantRequest) {
				ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
				BodyInserters.FormInserter<String> body = BodyInserters
						.fromFormData(OAuth2ParameterNames.GRANT_TYPE, authorizationGrantRequest.getGrantType().getValue());
				Set<String> scopes = clientRegistration.getScopes();
				if (!CollectionUtils.isEmpty(scopes)) {
					String scope = StringUtils.collectionToDelimitedString(scopes, " ");
					body.with(OAuth2ParameterNames.SCOPE, scope);
				}
				if (ClientAuthenticationMethod.POST.equals(clientRegistration.getClientAuthenticationMethod())) {
					body.with(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
					body.with(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
				}
				body.with("audience", baseURI+"/api/v2/");
				return body;
			}

		});
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
        ServerOAuth2AuthorizedClientExchangeFilterFunction oauth = new ServerOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
        oauth.setDefaultClientRegistrationId("auth0");
        return WebClient.builder()
        		.baseUrl(baseURI)
                .filter(oauth)
                .build();
	}
	
}

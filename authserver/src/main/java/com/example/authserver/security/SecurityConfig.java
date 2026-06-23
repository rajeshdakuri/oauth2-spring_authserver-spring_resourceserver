package com.example.authserver.security;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Configures the Spring Authorization Server security filter chain.
     * <p>
     * This filter chain is applied only to OAuth2 Authorization Server endpoints
     * such as authorization, token, JWK set, and UserInfo endpoints. It enables
     * OpenID Connect (OIDC) support, requires authentication for all authorization
     * server requests, and redirects unauthenticated browser users to the login page.
     * <p>
     * The configuration also enables JWT validation for endpoints that require
     * access token processing, such as the OIDC UserInfo endpoint.
     *
     * @param http HttpSecurity used to configure security settings
     * @return configured SecurityFilterChain for authorization server endpoints
     * @throws Exception if an error occurs while building the security configuration
     */

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http   //only applies to oauth2 endpoints
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer
                                .oidc(Customizer.withDefaults())    // Enable OpenID Connect 1.0
                )
                .authorizeHttpRequests((authorize) ->
                        authorize
                                .anyRequest().authenticated()
                )
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )        // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()));

        return http.build();
    }

    /**
     * Configures the default security filter chain for application endpoints.
     * <p>
     * This filter chain handles requests that are not processed by the
     * Authorization Server security filter chain. It requires users to
     * authenticate before accessing any endpoint and enables Spring
     * Security's default form-based login page.
     * <p>
     * The login page provided by this configuration is also used by the
     * Authorization Server when an unauthenticated user attempts to access
     * protected OAuth2 endpoints.
     *
     * @param http HttpSecurity used to configure security settings
     * @return configured SecurityFilterChain
     * @throws Exception if an error occurs while building the security configuration
     */

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize.requestMatchers("/signup").permitAll()
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /**
     * Creates an in-memory repository of OAuth2 registered clients.
     * <p>
     * The repository includes multiple client configurations demonstrating
     * different OAuth2 and OpenID Connect flows:
     * <p>
     * - rdcoffeeshop:
     * Uses Client Credentials Flow and receives self-contained JWT access tokens.
     * <p>
     * - rdcoffeeshopclient:
     * Uses Authorization Code Flow with Refresh Tokens and supports OpenID Connect.
     * <p>
     * - rdpublicclient:
     * Uses Authorization Code Flow with PKCE and Refresh Tokens, making it
     * suitable for public clients such as mobile applications and single-page applications.
     * <p>
     * All clients are stored in memory and are available to the Authorization Server
     * for authentication and token generation.
     *
     * @return InMemoryRegisteredClientRepository containing all registered clients
     */

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient clientCredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("rdcoffeeshop")
                .clientSecret("{noop}VxubZgAXyyTq9lGjj3qGvWNsHtE4SqTq")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scopes(scopeConfig -> scopeConfig.addAll(List.of(OidcScopes.OPENID, "ADMIN", "USER")))
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(10))
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build()).build();


        RegisteredClient authCodeClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("rdcoffeeshopclient")
                .clientSecret("{noop}Qw3rTy6UjMnB9zXcV2pL0sKjHn5TxQqB")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scope(OidcScopes.EMAIL)
                .clientSettings(ClientSettings.builder().requireProofKey(false).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(10))
                        .refreshTokenTimeToLive(Duration.ofHours(8)).reuseRefreshTokens(false)
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build()).build();

        RegisteredClient pkceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("rdpublicclient")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scope(OidcScopes.EMAIL)
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(10))
                        .refreshTokenTimeToLive(Duration.ofHours(8)).reuseRefreshTokens(false)
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build()).build();

        return new InMemoryRegisteredClientRepository(clientCredClient, authCodeClient, pkceClient);
    }

    /**
     * Creates a JWK source containing the RSA key pair used by the
     * Authorization Server for JWT signing and verification.
     * <p>
     * This method generates an RSA public/private key pair, converts
     * it into a JSON Web Key (JWK), and stores it in a JWK set.
     * The private key is used to sign JWT access tokens, while the
     * public key is exposed through the JWK Set endpoint so that
     * Resource Servers can verify token signatures.
     *
     * @return JWKSource containing the RSA key pair used by the
     * Authorization Server
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * Generates an RSA key pair used for signing and validating JWT tokens.
     * <p>
     * This method creates a 2048-bit RSA public/private key pair.
     * The private key is typically used by the Authorization Server
     * to sign JWT access tokens, while the public key is exposed
     * through the JWK Set endpoint and used by Resource Servers
     * to verify JWT signatures.
     *
     * @return generated RSA KeyPair containing a public key and private key
     * @throws IllegalStateException if RSA key generation fails
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * Creates a JwtDecoder used to validate and decode JWT tokens.
     * <p>
     * The decoder uses the keys available in the JWK source to verify
     * token signatures and validate JWT claims before processing them.
     * This bean is primarily used by OpenID Connect endpoints and
     * resource server functionality within the Authorization Server.
     *
     * @param jwkSource source containing the RSA keys used for JWT validation
     * @return configured JwtDecoder instance
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Creates the configuration settings for the Authorization Server.
     * <p>
     * This bean defines the Authorization Server's endpoint configuration
     * and issuer settings. When no custom settings are provided,
     * Spring Authorization Server uses its default endpoint mappings
     * such as /oauth2/authorize, /oauth2/token, and /oauth2/jwks.
     *
     * @return AuthorizationServerSettings containing the server configuration
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

   /* @Bean
    public AuthenticationProvider authenticationProvider(
            MyUserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {

        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider(userDetailsService);

        provider.setPasswordEncoder(passwordEncoder);

        return provider;
    }*/

    /**
     * Customizes JWT access tokens before they are issued by the
     * Authorization Server.
     * <p>
     * This customizer adds a custom "roles" claim to access tokens.
     * For Client Credentials Flow, the roles are derived from the
     * requested scopes. For Authorization Code Flow, the roles are
     * extracted from the authenticated user's authorities and added
     * to the token after removing the "ROLE_" prefix.
     * <p>
     * The generated roles claim can later be used by Resource Servers
     * to perform role-based authorization.
     *
     * @return OAuth2TokenCustomizer used to enrich JWT access tokens
     * with role information
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
                context.getClaims().claims((claims) -> {
                    //in client credentials grant type flow no end user involved so we are passing roles in the form of
                    //scope so we are extracting those and putting them in roles.
                    if (context.getAuthorizationGrantType().equals(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
                        Set<String> roles = context.getClaims().build().getClaim("scope");
                        claims.put("roles", roles);
                    } else if (context.getAuthorizationGrantType().equals(AuthorizationGrantType.AUTHORIZATION_CODE)) {
                        Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities())
                                .stream()
                                .map(c -> c.replaceFirst("^ROLE_", ""))
                                .collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
                        claims.put("roles", roles);
                    }
                });
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * From Spring Security 6.3 version
     *
     * @return
     */
    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }
}

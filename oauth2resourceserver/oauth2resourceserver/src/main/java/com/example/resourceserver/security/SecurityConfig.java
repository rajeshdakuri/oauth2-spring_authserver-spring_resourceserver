package com.example.resourceserver.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * Creates and configures the Spring Security filter chain for the application.
     * <p>
     * This method configures JWT-based authentication using OAuth2 Resource Server.
     * Requests matching '/secured/**' must contain a valid JWT access token,
     * while all other requests are allowed without authentication.
     * <p>
     * A custom JwtToRoleConverter is registered to extract roles from the JWT
     * and convert them into Spring Security authorities. These authorities are
     * later used by Spring Security for authorization decisions.
     *
     * @param http HttpSecurity object used to configure security settings
     * @return configured SecurityFilterChain instance
     * @throws Exception if an error occurs while building the security configuration
     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new JwtToRoleConverter());
        http.csrf(c -> c.disable())
                .authorizeHttpRequests(a -> a.requestMatchers("/secured/**").authenticated()
                        .anyRequest().permitAll())
                .oauth2ResourceServer(o -> o.
                        jwt(jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter)));
        return http.build();
    }
}

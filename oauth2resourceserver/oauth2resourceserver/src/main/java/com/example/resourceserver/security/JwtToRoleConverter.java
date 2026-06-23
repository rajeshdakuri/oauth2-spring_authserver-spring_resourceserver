package com.example.resourceserver.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Collectors;

/**
 * Converts a JWT token into a collection of Spring Security
 * {@link GrantedAuthority} objects.
 * This converter extracts roles from the {@code realm_access.roles}
 * claim present in a JWT issued by Keycloak and maps each role to
 * a Spring Security authority by prefixing it with {@code ROLE_}
 * <p>
 * Example JWT claim:
 *
 * <pre>
 * {
 *   "realm_access": {
 *     "roles": ["admin", "user"]
 *   }
 * }
 * Converted authorities:
 * ROLE_admin
 * ROLE_user
 * If the {@code realm_access} claim is missing or empty,
 * an empty collection of authorities is returned.
 * </p>
 *
 * @author Rajesh
 * @see Jwt
 * @see GrantedAuthority
 * @see SimpleGrantedAuthority
 */
public class JwtToRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    /**
     * Extracts roles from the JWT's {@code realm_access.roles} claim
     * and converts them into Spring Security authorities.
     *
     * @param token the JWT token containing role information
     * @return a collection of {@link GrantedAuthority} objects derived
     * from the roles present in the token; returns an empty
     * collection if no roles are found
     */
    @Override
    public Collection<GrantedAuthority> convert(Jwt token) {

        ArrayList<String> roles = (ArrayList<String>) token.getClaims().get("roles");
        if (roles == null || roles.isEmpty()) {
            return new ArrayList<>();
        }
        Collection<GrantedAuthority> returnValue = roles.stream().map(roleName -> "ROLE_" + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return returnValue;
    }
}


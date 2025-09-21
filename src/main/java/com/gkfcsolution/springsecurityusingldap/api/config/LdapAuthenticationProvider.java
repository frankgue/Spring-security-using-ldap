package com.gkfcsolution.springsecurityusingldap.api.config;

import com.unboundid.ldap.sdk.*;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Created on 2025 at 17:33
 * File: null.java
 * Project: Spring-security-using-ldap
 *
 * @author Frank GUEKENG
 * @date 21/09/2025
 * @time 17:33
 */
@Component
public class LdapAuthenticationProvider implements AuthenticationProvider {



    private final String ldapHost = "localhost";
    private final int ldapPort = 8389;
    private final String bindDN = "cn=admin,dc=springframework,dc=org";
    private final String bindPassword = "adminpassword";
    private final String baseDN = "ou=people,dc=springframework,dc=org";

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        try (LDAPConnection connection = new LDAPConnection(ldapHost, ldapPort, bindDN, bindPassword)){
            // Cherche l’utilisateur par uid
            Filter filter = Filter.createEqualityFilter("uid", username);
            SearchResult result = connection.search(baseDN, SearchScope.SUB, filter);

            if (result.getEntryCount() == 1){
                String userDN = result.getSearchEntries().get(0).getDN();

                // Vérifie login avec credentials
                try (LDAPConnection userCon = new LDAPConnection(ldapHost, ldapPort, userDN, password)){
                    // 🔑 Mapping des groupes -> rôles (exemple simple : ROLE_USER)
                    return new UsernamePasswordAuthenticationToken(
                            username,
                            password,
                            List.of(new SimpleGrantedAuthority("ROLE_USER"))
                    );
                }
            }
throw new BadCredentialsException("Utilisateur introuvable ou credentials invalides !");
        }catch (LDAPException e){
            throw new BadCredentialsException("Erreur LDAP : " + e.getMessage(), e);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}

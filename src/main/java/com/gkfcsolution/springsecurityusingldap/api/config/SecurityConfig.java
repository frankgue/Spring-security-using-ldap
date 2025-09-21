package com.gkfcsolution.springsecurityusingldap.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.ldap.LdapBindAuthenticationManagerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

/**
 * Created on 2025 at 17:11
 * File: null.java
 * Project: Spring-security-using-ldap
 *
 * @author Frank GUEKENG
 * @date 21/09/2025
 * @time 17:11
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public LdapContextSource contextSource() {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl("ldap://localhost:8389");
        contextSource.setBase("dc=springframework,dc=org");
        contextSource.setUserDn("cn=admin,dc=springframework,dc=org");
        contextSource.setPassword("adminpassword");
        contextSource.afterPropertiesSet();
        return contextSource;
    }

    @Bean
    public AuthenticationManager authenticationManager(LdapContextSource contextSource) {
        LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
        factory.setUserDnPatterns("uid={0},ou=people"); // Recherche des users
        return factory.createAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance(); // adapté si {noop}userPassword dans LDIF
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/public/**").permitAll()
                        .anyRequest().authenticated()
                )
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}

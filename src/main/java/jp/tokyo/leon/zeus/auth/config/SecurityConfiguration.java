package jp.tokyo.leon.zeus.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author longtao.guan
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(Customizer.withDefaults()).build();
    }

    /**
     * 验证流程
     * OAuth2ClientAuthenticationFilter ->
     * 	    Authentication authenticationResult = this.authenticationManager.authenticate(authenticationRequest);
     * ObservationAuthenticationManager ->
     *      Authentication authenticate(Authentication authentication)
     * ProviderManager ->
     *      Authentication authenticate(Authentication authentication)
     *
     *
     */
    @Bean
    @Order(2)
    public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());
        // @formatter:on

        return http.build();
    }
}

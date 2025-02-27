package ru.avdeev.eureka.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain uiSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .oauth2Client(Customizer.withDefaults())
                .oauth2Login(Customizer.withDefaults())
                .authorizeHttpRequests(customizer -> customizer
                        .requestMatchers(HttpMethod.POST, "**").permitAll()
                        .requestMatchers(HttpMethod.DELETE, "**").permitAll()
                        .requestMatchers(HttpMethod.PUT, "**").permitAll()
                        .requestMatchers(HttpMethod.PATCH, "**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/eureka/apps/*", "/eureka/instances/*", "/eureka/svips/*", "/eureka/vips/*").permitAll()
                        .anyRequest().hasAuthority("SCOPE_admin_server"))
                .oauth2ResourceServer(customizer -> customizer.jwt(Customizer.withDefaults()))
                .csrf(CsrfConfigurer::disable)
                .build();
    }
}

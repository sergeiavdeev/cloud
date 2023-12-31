package ru.avdeev.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
public class SecurityConfig {

    @Value("${logout.url}")
    private String logoutUrl;

    @Value("${login.post_url}")
    private String loginSuccessUrl;
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
                                                         ServerLogoutSuccessHandler logoutSuccessHandler,
                                                         ServerAuthenticationSuccessHandler loginSuccessHandler) {
        http.authorizeExchange((authorize) -> authorize
                        .pathMatchers(HttpMethod.POST, "/**").authenticated()
                        .anyExchange().permitAll()
                )
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(jwtSpec -> jwtSpec.jwtAuthenticationConverter(
                                source -> Mono.just(jwtAuthenticationConverter().convert(source)))

                        )
                )
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .oauth2Login(oAuth2LoginSpec -> oAuth2LoginSpec
                        .authenticationSuccessHandler(loginSuccessHandler))
                .logout(logoutSpec -> logoutSpec.logoutSuccessHandler(logoutSuccessHandler))
                .oauth2Client(Customizer.withDefaults())
            ;

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setPrincipalClaimName("preferred_username");
        converter.setJwtGrantedAuthoritiesConverter(jwt -> jwt.getClaimAsStringList("spring_roles").stream()
                .map(SimpleGrantedAuthority::new)
                .map(GrantedAuthority.class::cast)
                .toList()
        );
        return converter;
    }
    @Bean
    public ReactiveOAuth2UserService<OidcUserRequest, OidcUser> oAuth2UserService() {

        OidcUserService service = new OidcUserService();
        return userRequest -> {
            OidcUser user = service.loadUser(userRequest);
            List<String> roles = user.getClaimAsStringList("spring_roles");
            List<GrantedAuthority> authorities = roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .map(GrantedAuthority.class::cast)
                    .toList();
            return Mono.just(new DefaultOidcUser(authorities, user.getIdToken(), user.getUserInfo()));
        };
    }

    @Bean
    public GlobalFilter customFilter() {
        return new CustomGlobalFilter();
    }

    private static class CustomGlobalFilter implements GlobalFilter {

        @Override
        public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

            return ReactiveSecurityContextHolder.getContext()
                            .map(SecurityContext::getAuthentication)
                                    .flatMap(authentication -> {
                                        DefaultOidcUser user = (DefaultOidcUser) authentication.getPrincipal();
                                        HttpHeaders headers = exchange.getResponse().getHeaders();
                                        headers.add("X-Auth-User", URLEncoder.encode(user.getPreferredUsername(), StandardCharsets.UTF_8));
                                        headers.add("X-User-FirstName", URLEncoder.encode(user.getFamilyName(), StandardCharsets.UTF_8));
                                        headers.add("X-User-LastName", URLEncoder.encode(user.getGivenName(), StandardCharsets.UTF_8));
                                        headers.add("X-User-Granted", authentication.getAuthorities().stream()
                                                .map(GrantedAuthority::getAuthority)
                                                .map(s -> s.replace("ROLE_", ""))
                                                .collect(Collectors.joining(",")));
                                        //updateCookie(exchange.getResponse(), user);
                                        return chain.filter(exchange);
                                    })
                            .switchIfEmpty(chain.filter(exchange));
        }
    }

    @Bean
    ServerLogoutSuccessHandler keycloakLogoutSuccessHandler(ReactiveClientRegistrationRepository repository) {
        OidcClientInitiatedServerLogoutSuccessHandler handler =
                new OidcClientInitiatedServerLogoutSuccessHandler(repository);

        handler.setPostLogoutRedirectUri(logoutUrl);
        return handler;
    }

    @Bean
    ServerAuthenticationSuccessHandler authenticationSuccessHandler() {

        RedirectServerAuthenticationSuccessHandler handler = new RedirectServerAuthenticationSuccessHandler();
        handler.setLocation(URI.create(loginSuccessUrl));
        return handler;
    }
}

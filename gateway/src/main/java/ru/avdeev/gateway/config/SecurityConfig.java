package ru.avdeev.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;

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
                        .pathMatchers(HttpMethod.DELETE, "/**").authenticated()
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
                .addFilterAfter((exchange, chain) -> {
                    exchange.getResponse().getHeaders().add("Access-Control-Allow-Origin", "http://localhost:5173");
                    exchange.getResponse().getHeaders().add("Access-Control-Allow-Credentials", "true");
                    exchange.getResponse().getHeaders().add("Access-Control-Allow-Headers", "*,x-requested-with,content-type");
                    exchange.getResponse().getHeaders().add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
                    return chain.filter(exchange);
                }, SecurityWebFiltersOrder.FIRST)
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

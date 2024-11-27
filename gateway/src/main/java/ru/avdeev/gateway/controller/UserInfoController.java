package ru.avdeev.gateway.controller;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import ru.avdeev.gateway.dto.UserDto;

import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/user")
public class UserInfoController {

    @GetMapping("/info")
    public Mono<UserDto> getUserInfo(ServerHttpResponse response) {

        response.setStatusCode(HttpStatusCode.valueOf(401));

        return ReactiveSecurityContextHolder.getContext()
                    .map(SecurityContext::getAuthentication)
                    .map(authentication -> {
                        DefaultOidcUser user = (DefaultOidcUser) authentication.getPrincipal();

                        response.setStatusCode(HttpStatusCode.valueOf(200));
                        return UserDto.builder()
                                .uuid(UUID.fromString(user.getName()))
                                .firstName(user.getGivenName())
                                .lastName(user.getFamilyName())
                                .roles(authentication.getAuthorities().stream()
                                        .map(GrantedAuthority::getAuthority)
                                        .map(s -> s.replace("ROLE_", ""))
                                        .collect(Collectors.toList()))
                                .build();
                    })
                .switchIfEmpty(Mono.just(UserDto.builder().build()))
                ;

    }
}

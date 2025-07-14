package com.kosta.gatewayservice.config;

import com.kosta.gatewayservice.auth.jwt.JwtAuthorizationFilter;
import com.kosta.gatewayservice.filter.LoggingGatewayFilterFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class GatewayConfig {

    private final JwtAuthorizationFilter jwtAuthorizationFilter;

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder, LoggingGatewayFilterFactory loggingGatewayFilterFactory) {
        return builder.routes()
                .route("user-service", r -> r
                        .path("/oauth2/**", "/login/**", "/api/member/**", "/token/**",
                                "/api/send-code","/api/verify-code")
                        .filters(f -> f
                                .filter(jwtAuthorizationFilter)
                                .filter(loggingGatewayFilterFactory.apply(new LoggingGatewayFilterFactory.Config()))
                        )
                        .uri("lb://user-service"))


                .route("bankdetail-service", r -> r
                        .path("/bank-detail/**")
                        .filters(f -> f
                                .filter(jwtAuthorizationFilter)
                                .filter(loggingGatewayFilterFactory.apply(new LoggingGatewayFilterFactory.Config()))
                        )
                        .uri("lb://bankdetail-service"))


                .build();
    }
}

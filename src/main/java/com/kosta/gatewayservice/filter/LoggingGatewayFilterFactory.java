package com.kosta.gatewayservice.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

@Slf4j
@Component
public class LoggingGatewayFilterFactory extends AbstractGatewayFilterFactory<LoggingGatewayFilterFactory.Config> {

    public LoggingGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerWebExchange ex = exchange;

            log.info("========== [GATEWAY LOGGING] ==========");
            log.info("[Request URI]   {}", ex.getRequest().getURI());
            log.info("[HTTP Method]   {}", ex.getRequest().getMethod());

            Object route = ex.getAttribute("org.springframework.cloud.gateway.support.ServerWebExchangeUtils.gatewayRoute");
            log.info("[Route ID]      {}", route);
            log.info("=======================================");

            return chain.filter(exchange);
        };
    }

    public static class Config {

    }
}

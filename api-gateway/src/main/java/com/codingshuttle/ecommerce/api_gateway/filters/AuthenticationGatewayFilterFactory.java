package com.codingshuttle.ecommerce.api_gateway.filters;

import com.codingshuttle.ecommerce.api_gateway.service.JwtService;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

@Component
@Slf4j
public class AuthenticationGatewayFilterFactory extends AbstractGatewayFilterFactory<AuthenticationGatewayFilterFactory.Config> {

    private final JwtService jwtService;

    public AuthenticationGatewayFilterFactory(JwtService jwtService) {
        super(Config.class);
        this.jwtService = jwtService;
    }

//    @Override
//    public GatewayFilter apply(Config config) {
//        return (exchange, chain) -> {
//
//            String authorizationHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
//            if (authorizationHeader == null) {
//                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
//                return exchange.getResponse().setComplete();
//            }
//
//            String token = authorizationHeader.split("Bearer ")[1];
//            Long userId = jwtService.getUserIdFromToken(token);
//
//            exchange.getRequest()
//                    .mutate()
//                    .header("X-User-Id", userId.toString())
//                    .build();
//
//            return chain.filter(exchange);
//        };
//    }

//    @Override
//    public GatewayFilter apply(Config config) {
//        return (exchange, chain) -> {
//            String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
//
//            if(authHeader == null){
//                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
//                return exchange.getResponse().setComplete();
//            }
//
//            String token = authHeader.split("Bearer ")[1];
//
//            Long userId = jwtService.getUserIdFromToken(token);
//
//            exchange = (ServerWebExchange) exchange.getRequest()
//                    .mutate()
//                    .header("X-User-Id", userId.toString())
//                    .build();
////
////            return chain.filter(exchange);
//

    /// /            // Create a new mutated request with the additional header
//            ServerHttpRequest mutatedRequest = exchange.getRequest()
//                    .mutate()
//                    .header("X-User-Id", userId.toString())
//                    .build();
//
//            // Update the exchange with the new request
//            ServerWebExchange mutatedExchange = exchange.mutate()
//                    .request(mutatedRequest)
//                    .build();
//
//            return chain.filter(mutatedExchange);
//        };
//    }
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            if (!config.isEnabled) return chain.filter(exchange);

            String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            String token = authHeader.substring(7); // safer than split

            Long userId = jwtService.getUserIdFromToken(token);

            // Create a new mutated request with the additional header
            ServerHttpRequest mutatedRequest = exchange.getRequest()
                    .mutate()
                    .header("X-User-Id", userId.toString())
                    .build();

            log.info("Extracted User ID: {}", userId);

            // Update the exchange with the new request
            ServerWebExchange mutatedExchange = exchange.mutate()
                    .request(mutatedRequest)
                    .build();

            log.info("Injected header X-User-Id = {}", userId);

            return chain.filter(mutatedExchange);
        };
    }


    @Data
    public static class Config {
        private boolean isEnabled;
    }

}

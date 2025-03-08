package com.yupi.yuojbackendgateway.filter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.yupi.yuojbackendcommon.utils.JwtUtil;
import com.yupi.yuojbackendcommon.utils.ThreadLocalUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

@Component
@Slf4j
public class JwtAuthenticationFilter implements GlobalFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        log.info("jwt拦截开始");

        String token = exchange.getRequest().getHeaders().getFirst("Authorization");
        // 检查 token 是否以 "Bearer " 开头
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7); // 去掉 "Bearer " 前缀
        }
        log.info("jwt拦截开始{}",token);
        if (token == null || !isValidToken(token)) {
            ServerHttpRequest serverHttpRequest = exchange.getRequest();
            String path = serverHttpRequest.getURI().getPath();
            if (path.contains("/login")) {
                log.info("放行登录请求");
                return chain.filter(exchange); // 继续处理请求
            }
            // 设置重定向到登录页面
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);

            return exchange.getResponse().setComplete(); // 完成响应
        }

        // 继续处理请求
        return chain.filter(exchange);
    }

    private boolean isValidToken(String token) {
        try {
            Map<String, Object> claims = JwtUtil.parseToken(token);
            log.info("Token 有效");
            return true;
        } catch (JWTVerificationException e) {
            log.error("Token 验证失败: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Token 解析时出现异常: {}", e.getMessage());
            return false;
        }
    }
}
package com.study.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.study.config.WhiteUrlsConfig;
import com.study.constant.AuthConstants;
import com.study.constant.BusinessEnum;
import com.study.constant.HttpConstants;
import com.study.model.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Date;

/**
 * 全局token过滤器
 * 存放位置：请求头的Authorization bearer token
 */
@Component
@Slf4j
public class AuthFilter implements GlobalFilter, Ordered {

    @Autowired
    private WhiteUrlsConfig whiteUrlsConfig;

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    /**
     * 校验token
     * 1.获取请求路径
     * 2.判断请求路径是否需要认证
     *
     *
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 获取请求对象
        ServerHttpRequest request = exchange.getRequest();
        // 获取请求路径
        String path = request.getPath().toString();
        // 判断路径是否在白名单中
        if (whiteUrlsConfig.getAllowUrls().contains(path)) {
            return chain.filter(exchange);
        }
        // 不在白名单中需要进行验证
        String authorizationValue = request.getHeaders().getFirst(AuthConstants.AUTHORIZATION);
        if (StringUtils.hasText(authorizationValue)) {
            // 获取token
            String tokenValue = authorizationValue.replace(AuthConstants.BEARER, "");
            if (StringUtils.hasText(tokenValue) && Boolean.TRUE.equals(stringRedisTemplate.hasKey(AuthConstants.LOGIN_TOKEN_PREFIX + tokenValue))) {
                //认证通过
                return chain.filter(exchange);
            }
        }
        // 非法请求
        log.error("非法请求,时间:{},请求路径:{}",new Date(),path);
        // 设置响应信息
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().set(HttpConstants.CONTENT_TYPE,HttpConstants.APPLICATION_JSON);
        Result<Object> result = Result.fali(BusinessEnum.UN_AUTHORIZATION);
        ObjectMapper objectMapper = new ObjectMapper();
        byte[] bytes = new byte[0];
        try {
            bytes = objectMapper.writeValueAsBytes(result);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        DataBuffer dataBuffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(dataBuffer));
    }

    @Override
    public int getOrder() {
        return 0;
    }
}

package com.study.constant;

/**
 * 认证授权常量类
 */
public interface AuthConstants {

    /**
     * 存放token的Key
     */
    String AUTHORIZATION = "Authorization";

    /**
     * token前缀
     */
    String BEARER = "bearer ";

    /**
     * redis token前缀
     */
    String LOGIN_TOKEN_PREFIX = "login_token";
}

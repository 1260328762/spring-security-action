// package com.cl.config;
//
// import org.springframework.context.annotation.Configuration;
// import org.springframework.core.annotation.Order;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//
// @Configuration
// @Order(-1)
// 为不同的路径配置不同的配置
// public class WebSecurityConfig2 extends WebSecurityConfigurerAdapter {
//
//     @Override
//     protected void configure(HttpSecurity http) throws Exception {
//         http.csrf().disable()
//                 .antMatcher("/user/**")
//                 .authorizeRequests()
//                 .anyRequest().permitAll()
//                 .and()
//                 .formLogin()
//                 .and()
//                 .sessionManagement()
//                 .sessionConcurrency(configure -> {
//                     configure.maximumSessions(1);
//                 });
//     }
// }

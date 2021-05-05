// package com.cl.config;
//
// import org.springframework.context.annotation.Configuration;
// import org.springframework.core.annotation.Order;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//
// /**
//  * 多配置独立运行
//  */
// @Configuration
// public class WebSecurityMultiConfig {
//
//     @Configuration
//     @Order(1)
//     static class Config1 extends WebSecurityConfigurerAdapter {
//         @Override
//         protected void configure(HttpSecurity http) throws Exception {
//             http.antMatcher("/user/**")
//                     .authorizeRequests()
//                     .anyRequest().permitAll()
//                     .and()
//                     .csrf().disable();
//         }
//     }
//
//     @Configuration
//     @Order(2)
//     static class Config2 extends WebSecurityConfigurerAdapter {
//         @Override
//         protected void configure(HttpSecurity http) throws Exception {
//             http.antMatcher("/user2/**")
//                     .authorizeRequests()
//                     .anyRequest().permitAll()
//                     .and()
//                     .csrf().disable();
//         }
//     }
// }

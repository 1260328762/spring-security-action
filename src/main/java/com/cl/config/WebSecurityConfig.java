package com.cl.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@Order(0)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/user/login").authenticated()
                .antMatchers("/**").permitAll()
                .and()
                .formLogin()
                .and()
                .sessionManagement()
                .sessionConcurrency(configure -> {
                    configure.maximumSessions(1);
                });

    }
}

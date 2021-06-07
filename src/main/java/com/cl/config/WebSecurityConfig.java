package com.cl.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

@Configuration
@Order(0)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .accessDecisionManager(new AffirmativeBased(Arrays.asList(accessDecisionVoter(), new WebExpressionVoter())))
                .antMatchers("/role/admin").hasRole("admin")
                .antMatchers("/**").authenticated()
                .and()
                .exceptionHandling()
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.getWriter().print("Access Deny");
                    response.flushBuffer();
                })
                .and()
                .formLogin()
                .and()
                .sessionManagement()
                .sessionConcurrency(configure -> {
                    configure.maximumSessions(-1);
                    configure.sessionRegistry(sessionRegistry());
                })
                .and()
                .rememberMe()
                .key("123");
    }

    public AccessDecisionVoter<?> accessDecisionVoter() {
        return new AccessDecisionVoter<Object>() {
            @Override
            public boolean supports(ConfigAttribute attribute) {
                return true;
            }

            @Override
            public boolean supports(Class<?> clazz) {
                return true;
            }

            @Override
            public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
                System.out.println("authentication: " + authentication);
                return authentication instanceof AnonymousAuthenticationToken ? -1 : 0;
            }
        };
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("123456")
                .authorities(Collections.emptyList())
                .build();
        UserDetails user2 = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("123456")
                .authorities(new SimpleGrantedAuthority("ROLE_admin"))
                .build();
        auth.userDetailsService(new InMemoryUserDetailsManager(user, user2));
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
    }


    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }
}

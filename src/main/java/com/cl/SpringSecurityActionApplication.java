package com.cl;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
@Controller
public class SpringSecurityActionApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityActionApplication.class, args);

        List<Thread> threads = new ArrayList<>(700);
        for (int i = 0; i < 700; i++) {
            threads.add(new Thread(){
                @Override
                public void run() {
                    System.out.println("");
                }
            });
        }

        UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter = new UsernamePasswordAuthenticationFilter();
    }

    @GetMapping("/user/logout")
    @ResponseBody
    public String logout() {
        System.out.println("logout");
        return "logout";
    }

    @GetMapping("/user/login")
    @ResponseBody
    public String login() {
        System.out.println("login");
        return "login";
    }

}

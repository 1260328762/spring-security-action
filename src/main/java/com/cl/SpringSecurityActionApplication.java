package com.cl;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@SpringBootApplication
@Controller
public class SpringSecurityActionApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityActionApplication.class, args);

        AtomicInteger integer = new AtomicInteger();
        List<Thread> threads = new ArrayList<>(700);
        for (int i = 0; i < 7000; i++) {
            new Thread(){
                @Override
                public void run() {
                    System.out.println(integer.getAndIncrement());
                    try {
                        Thread.sleep(900000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }.start();
        }

        UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
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

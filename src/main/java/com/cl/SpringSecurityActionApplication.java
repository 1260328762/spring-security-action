package com.cl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Collections;

@SpringBootApplication
@Controller
public class SpringSecurityActionApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityActionApplication.class, args);
    }

    @Autowired
    private SessionRegistry sessionRegistry;


    @GetMapping("/role/admin")
    @ResponseBody
    public String roleAdmin() {
        return "You have role [admin]";
    }

    @GetMapping("/user/logout")
    @ResponseBody
    public String logout() {
        System.out.println("logout");
        return "logout";
    }

    @GetMapping("/user/login")
    @ResponseBody
    public String login(HttpServletRequest request) {
        HttpSession session = request.getSession();
        session.setAttribute("test", "1");
        session.getAttribute("test2");
        System.out.println("login");
        sessionRegistry.getAllPrincipals().forEach(System.out::println);
        System.out.println(sessionRegistry.getAllSessions(new User("user", "", Collections.emptyList()),
                true));
        return "login";
    }

}

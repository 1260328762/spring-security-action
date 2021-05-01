package com.cl;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

@RestController
public class LoginController {

    @RequestMapping("login")
    public void login(HttpServletRequest request) throws ServletException {
        request.login("user", "wer");
    }
}

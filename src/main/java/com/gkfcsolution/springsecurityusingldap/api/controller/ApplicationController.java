package com.gkfcsolution.springsecurityusingldap.api.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created on 2025 at 17:03
 * File: null.java
 * Project: Spring-security-using-ldap
 *
 * @author Frank GUEKENG
 * @date 21/09/2025
 * @time 17:03
 */
@RestController
@RequestMapping("/api/v1/rest")
public class ApplicationController {

    @GetMapping("/secure")
    public String secureMethod(){
        return "Secure method";
    }

}

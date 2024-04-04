package jp.tokyo.leon.zeus.auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author leon
 * @date 2024/4/2 22:26
 */
@RestController
public class HelloController {

    @GetMapping("/auth/hello")
    public String helloAuth() {
        return "hello auth";
    }
}

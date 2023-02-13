package com.example.springsecurity6.demo;

import com.example.springsecurity6.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
@RequiredArgsConstructor
public class DemoController {
    @GetMapping
    public ResponseEntity<Object> whoami() {
        // TODO: get the current user by using SecurityContextHolder
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        //omit the password
        if (principal instanceof User) {
            ((User) principal).setPassword(null);
        }
        return ResponseEntity.ok(principal);
    }
}

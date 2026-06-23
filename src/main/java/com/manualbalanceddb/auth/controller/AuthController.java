package com.manualbalanceddb.auth.controller;

import com.manualbalanceddb.auth.util.*;

import jakarta.annotation.PostConstruct;

import com.manualbalanceddb.auth.dto.*;
import com.manualbalanceddb.auth.model.*;
import com.manualbalanceddb.auth.respository.UserRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.data.mongodb.core.MongoTemplate;
import java.util.List;

import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
@RestController
@RequestMapping("/api/auth")

public class AuthController {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private MongoTemplate mongoTemplate;

    @Autowired
    private JwtUtil jwtUtil;
    @GetMapping("/all")
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        Optional<User> optionalUser = userRepository.findByEmail(request.getEmail());

        if( optionalUser.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new AuthResponse("Inavlid email or password", null, null));
        }

        User user = optionalUser.get();
        if(!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new AuthResponse("Invalid email or password", null, null));
        }
        String token = jwtUtil.generateToken(user.getEmail());
        UserDto userDto = new UserDto(user.getId(), user.getName(),user.getEmail(), user.getCreatedDate());
        return ResponseEntity.ok(new AuthResponse("Login successfull", token, userDto));
    }

    
    @GetMapping("/db")
    public String dbName() {

        String db =
            mongoTemplate.getDb().getName();

        System.out.println(
            "DATABASE = " + db
        );

        return db;
    }

    

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {       
        Optional<User> existingUser = userRepository.findByEmail(request.getEmail());
        if (existingUser.isPresent()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new AuthResponse("Email already registered", null, null));
        }

    
        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setCreatedDate(request.getCreatedDate());


        userRepository.save(user);
        String token = jwtUtil.generateToken(user.getEmail());
        UserDto userDto = new UserDto(user.getId(), user.getName() ,user.getEmail(), user.getCreatedDate());

        return ResponseEntity.status(HttpStatus.CREATED).body(new AuthResponse("User registered successfully", token, userDto));
    }
}
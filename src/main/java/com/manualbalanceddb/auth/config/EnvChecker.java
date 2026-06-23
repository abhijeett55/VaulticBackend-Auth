package com.manualbalanceddb.auth.config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class EnvChecker {

    @Value("${MONGODB_URI:NOT_FOUND}")
    private String mongoUri;

    @PostConstruct
    public void init() {
        System.out.println("MONGO URI = " + mongoUri);
    }
}
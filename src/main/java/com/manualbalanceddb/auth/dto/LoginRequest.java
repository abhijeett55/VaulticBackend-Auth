package com.manualbalanceddb.auth.dto;

import lombok.Data;

@Data
public class LoginRequest {
    private String name;
    private String email;
    private String password;


    public LoginRequest() { }

    public LoginRequest(String name, String email, String password) {
        this.name = name;
        this.email = email;
        this.password = password;
    }
}
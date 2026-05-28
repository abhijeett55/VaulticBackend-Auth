package com.manualbalanceddb.auth.dto;

import lombok.Data;

@Data
public class RegisterRequest {
    private String name;
    private String email;
    private String password;
    private String createdDate;

    public RegisterRequest() { }

    public RegisterRequest(String name, String email, String password, String createdDate) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.createdDate = createdDate;
    }
}
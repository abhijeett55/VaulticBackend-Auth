package com.manualbalanceddb.auth.dto;
import lombok.Data;

@Data
public class AuthResponse {
    private String message;
    private String token;
    private UserDto user;

    public AuthResponse() {}
    public AuthResponse(String message , String token, UserDto user) {
        this.message = message;
        this.token = token;
        this.user = user;
    }
}
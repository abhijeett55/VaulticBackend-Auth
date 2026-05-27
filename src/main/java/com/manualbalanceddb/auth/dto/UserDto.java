package com.manualbalanceddb.auth.dto;

import lombok.Data;

@Data
public class UserDto {
    private String id;
    private String name;
    private String email;

    public UserDto() { }

    public UserDto(String id, String name, String email) {
        this.id =  id;
        this.name = name;
        this.email = email;
    }
}
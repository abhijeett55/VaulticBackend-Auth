package com.manualbalanceddb.auth.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import lombok.Data;

@Data
@Document(collection = "users")
public class User {
    
    @Id
    private String id;
    @Indexed(unique = true)
    private String email;
    private String name;
    private String password;
    private String createdDate;

    public User() { }

    public User(String email, String name, String password, String createdDate) {
        this.email = email;
        this.name = name;
        this.password = password;
        this.createdDate = createdDate;
    }

}
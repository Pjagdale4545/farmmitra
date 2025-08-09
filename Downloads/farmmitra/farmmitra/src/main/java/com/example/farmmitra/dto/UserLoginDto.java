package com.example.farmmitra.dto;

public class UserLoginDto {
    private String username;
    private String password;

    // Getters
    public String getUsername() {
        return username;
    }
    public String getPassword() {
        return password;
    }

    // Setters
    public void setUsername(String username) {
        this.username = username;
    }
    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String toString() {
        return "UserLoginDto{" +
               "username='" + username + '\'' +
               ", password='[PROTECTED]'" +
               '}';
    }
}
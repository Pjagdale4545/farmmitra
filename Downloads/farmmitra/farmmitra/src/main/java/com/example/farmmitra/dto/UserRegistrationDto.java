package com.example.farmmitra.dto;

public class UserRegistrationDto {
    private String username;
    private String password;
    private String email;
    private String fullName;
    private String role; // Will be set by the service/controller (e.g., "BUYER")

    // Getters
    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public String getEmail() { return email; }
    public String getFullName() { return fullName; }
    public String getRole() { return role; }

    // Setters
    public void setUsername(String username) { this.username = username; }
    public void setPassword(String password) { this.password = password; }
    public void setEmail(String email) { this.email = email; }
    public void setFullName(String fullName) { this.fullName = fullName; }
    public void setRole(String role) { this.role = role; }

    @Override
    public String toString() {
        return "UserRegistrationDto{" +
               "username='" + username + '\'' +
               ", password='[PROTECTED]'" +
               ", email='" + email + '\'' +
               ", fullName='" + fullName + '\'' +
               ", role='" + role + '\'' +
               '}';
    }
}
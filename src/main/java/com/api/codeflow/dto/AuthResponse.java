package com.api.codeflow.dto;

import lombok.Data;

import java.util.List;

@Data
public class AuthResponse {
    private String token;
    private String username;
    private List<String> roles;
}

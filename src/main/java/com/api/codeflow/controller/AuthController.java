package com.api.codeflow.controller;

import com.api.codeflow.dto.AuthDto;
import com.api.codeflow.dto.RegisterDto;
import com.api.codeflow.exception.EmailIsTakenException;
import com.api.codeflow.exception.UsernameIsTakenException;
import com.api.codeflow.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;

    @PostMapping("/register")
    @ResponseBody
    public ResponseEntity<?> register(RegisterDto dto) {
        try {
            userService.register(dto);
            return ResponseEntity.ok("User registered successfully");
        } catch (UsernameIsTakenException | EmailIsTakenException | IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            // todo: log exception
            return new ResponseEntity<>("Server error :(", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/login")
    @ResponseBody
    public ResponseEntity<?> login(AuthDto dto) {
        try {
            return ResponseEntity.ok(userService.login(dto));
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>("Invalid username or password", HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            // todo: log exception
            return new ResponseEntity<>("Server error :(", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}

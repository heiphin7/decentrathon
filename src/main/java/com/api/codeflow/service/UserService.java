package com.api.codeflow.service;

import com.api.codeflow.dto.AuthDto;
import com.api.codeflow.dto.AuthResponse;
import com.api.codeflow.dto.RegisterDto;
import com.api.codeflow.exception.EmailIsTakenException;
import com.api.codeflow.exception.UsernameIsTakenException;
import com.api.codeflow.jwt.JwtTokenUtils;
import com.api.codeflow.model.Role;
import com.api.codeflow.model.User;
import com.api.codeflow.model.UserDetails;
import com.api.codeflow.repository.RoleRepository;
import com.api.codeflow.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final RoleRepository roleRepository;
    private final JwtTokenUtils jwtTokenUtils;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    public void register(RegisterDto dto) throws UsernameIsTakenException,
                                                 EmailIsTakenException,
                                                 IllegalArgumentException {
        if (dto.getUsername().length() < 4 || dto.getUsername().length() > 20) {
            throw new IllegalArgumentException("Username must be between 4 and 20 characters");
        }

        if (dto.getPassword().length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters");
        }

        String email = dto.getEmail();
        String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";

        if (email == null || !email.matches(emailRegex)) {
            throw new IllegalArgumentException("Invalid email address");
        }

        if (userRepository.existsByEmail(dto.getEmail())) {
            throw new EmailIsTakenException("Email is already taken!");
        }

        if (userRepository.existsByUsername(dto.getUsername())) {
            throw new UsernameIsTakenException("Username is already taken!");
        }

        Role role = roleRepository.findByName("ROLE_USER");

        // If everything is OK, create & save new User
        User user = new User();
        user.setEmail(dto.getEmail());

        // encode password
        user.setPassword(bCryptPasswordEncoder.encode(dto.getPassword()));
        user.setRoles(Set.of(
                role // role_user
        ));

        userRepository.save(user);
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    public AuthResponse login(AuthDto dto) throws BadCredentialsException {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        dto.getUsername(),
                        dto.getPassword()
                )
        );

        UserDetails userDetails = (UserDetails) userDetailsService.loadUserByUsername(dto.getUsername());
        String token = jwtTokenUtils.generateAccessToken(userDetails);

        AuthResponse authResponse = new AuthResponse();
        authResponse.setToken(token);
        authResponse.setUsername(dto.getUsername());
        authResponse.setRoles(
                userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList())
        );

        return authResponse;
    }
}

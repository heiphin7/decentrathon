package com.api.codeflow.service;

import com.api.codeflow.model.User;
import com.api.codeflow.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(
                        () -> new UsernameNotFoundException("Пользователь с именем " + username + " не найден!")
                );

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),

                user.getRoles()
                        .stream()
                        .map(role -> new SimpleGrantedAuthority(role.getName())
                ).collect(Collectors.toList())
        );
    }
}

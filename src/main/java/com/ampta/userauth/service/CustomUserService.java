package com.ampta.userauth.service;

import com.ampta.userauth.entity.UserAuth;
import com.ampta.userauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserAuth userAuth = userRepository.findByEmail(username).get();
        UserDetails userDetails = User.builder()
                .username(userAuth.getEmail())
                .password(userAuth.getPassword())
                .roles(userAuth.getRole())
                .build();

        return userDetails;
    }
}

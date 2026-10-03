package com.ampta.userauth.service.impl;

import com.ampta.userauth.dto.LoginRequest;
import com.ampta.userauth.dto.LoginResponse;
import com.ampta.userauth.dto.UserRequest;
import com.ampta.userauth.dto.UserResponse;
import com.ampta.userauth.entity.UserAuth;
import com.ampta.userauth.repository.UserRepository;
import com.ampta.userauth.service.JwtService;
import com.ampta.userauth.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    public UserResponse registerUser(UserRequest request) {
        UserAuth userAuth = modelMapper.map(request, UserAuth.class);
        userAuth.setPassword(passwordEncoder.encode(request.getPassword()));
        UserAuth savedUser = userRepository.save(userAuth);

        log.info("Created User with email: {}", savedUser.getEmail());
        return modelMapper.map(savedUser, UserResponse.class);
    }


    @Override
    public List<UserResponse> getAllUsers() {
        return userRepository.findByRole("user")
                .stream()
                .map(user -> modelMapper.map(user, UserResponse.class))
                .collect(Collectors.toList());
    }


    @Override
    public UserResponse getUserById(Long id) {
        UserAuth user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + id));
        return modelMapper.map(user, UserResponse.class);
    }

    @Override
    public LoginResponse login(LoginRequest request) {

        try{
            authenticationManager.authenticate(UsernamePasswordAuthenticationToken.
                    unauthenticated(request.getEmail(), request.getPassword()));
        }catch (AuthenticationException e){
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username and password");
        }

        UserAuth loggedUser = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + request.getEmail()));

        LoginResponse response = modelMapper.map(loggedUser, LoginResponse.class);
        response.setToken(jwtService.generateToken(loggedUser.getEmail(), loggedUser.getRole()));

        return response;
    }



    @Override
    public UserResponse updateUser(Long id, UserRequest request) {

        if(userRepository.existsByUsername(request.getUsername())){
            throw new IllegalArgumentException("Username already exists: " + request.getEmail());
        }

        if(userRepository.existsByEmail(request.getEmail())){
            throw new IllegalArgumentException("Email already exists: " + request.getEmail());
        }

        UserAuth existingUser = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + id));

        existingUser.setEmail(request.getEmail());
        existingUser.setUsername(request.getUsername());
        UserAuth savedUser = userRepository.save(existingUser);
        return modelMapper.map(savedUser, UserResponse.class) ;
    }

    @Override
    public UserResponse getProfile(String email) {
        UserAuth user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found with email: " + email));
        return modelMapper.map(user, UserResponse.class);
    }
}

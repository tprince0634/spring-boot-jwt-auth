package com.ampta.userauth.service;

import com.ampta.userauth.dto.LoginRequest;
import com.ampta.userauth.dto.LoginResponse;
import com.ampta.userauth.dto.UserRequest;
import com.ampta.userauth.dto.UserResponse;

import java.util.List;

public interface UserService {

    UserResponse registerUser(UserRequest request);
    List<UserResponse> getAllUsers();
    UserResponse getUserById(Long id);
    LoginResponse login(LoginRequest request);
    UserResponse updateUser(Long id, UserRequest request);

    UserResponse getProfile(String email);


}

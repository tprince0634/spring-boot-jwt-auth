package com.ampta.userauth.OverAllRequestFlow.Login;

public class Demo {

/*
Client
  ↓
POST /users/login
  ↓
SecurityFilterChain
  ↓
permitAll()
  ↓
Controller
  ↓
UserServiceImpl.login()
  ↓
AuthenticationManager
  ↓
DaoAuthenticationProvider
  ↓
CustomUserService
  ↓
Database
  ↓
BCrypt Password Comparison
  ↓
Authentication Successful
  ↓
Find User By Email
  ↓
Generate JWT
  ↓
LoginResponse
  ↓
Client*/
}

package com.ampta.userauth.OverAllRequestFlow.Register;

public class Demo {

/*

Client
  ↓
POST /users/register
  ↓
SecurityFilterChain
  ↓
permitAll()
  ↓
Controller
  ↓
UserServiceImpl.registerUser()
  ↓
ModelMapper
  ↓
UserAuth Entity
  ↓
BCrypt PasswordEncoder
  ↓
Repository.save()
  ↓
Database
  ↓
UserResponse
  ↓
Client*/

}

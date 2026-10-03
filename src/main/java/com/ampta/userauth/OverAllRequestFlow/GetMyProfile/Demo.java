package com.ampta.userauth.OverAllRequestFlow.GetMyProfile;

public class Demo {

    /*
    GET /users/me
    Authorization: Bearer JWT
        │
                ▼
    JwtFilter.java
        │
                ▼
    Read Authorization Header
        │
                ▼
    Remove "Bearer "
            │
            ▼
    Full JWT
        │
                ▼
    Validate JWT
        │
                ▼
    Extract Subject (Email)
        │
                ▼
    CustomUserService
        │
                ▼
    UserDetails
        │
                ▼
    Authentication Object
        │
                ▼
    SecurityContext
        │
                ▼
    Authorization
        │
                ▼
    Controller
        │
                ▼
    getProfile(email)
        │
                ▼
    UserRepository
        │
                ▼
    Database
        │
                ▼
    UserResponse
        │
                ▼
    Client

    */

}

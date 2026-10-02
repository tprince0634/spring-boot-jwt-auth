package com.ampta.userauth.config;

import com.ampta.userauth.filter.JwtFilter;
import com.ampta.userauth.service.CustomUserService;
import com.ampta.userauth.service.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityFilterConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity httpSecurity,
            JwtService jwtService,
            CustomUserService customUserService,
            AuthenticationEntryPoint authenticationEntryPoint) {

        // Create our custom JWT filter.
        // This filter extracts the JWT from the Authorization header,
        // validates the token, and sets the authenticated user
        // in Spring Security's SecurityContext.
        JwtFilter jwtAuthenticationFilter =
                new JwtFilter(jwtService, customUserService);

        return httpSecurity

                // Disable CSRF because this application uses JWT-based
                // stateless authentication instead of server-side sessions.
                .csrf(csrf -> csrf.disable())

                // Define authorization rules for different endpoints.
                .authorizeHttpRequests(
                        request -> request

                                // These endpoints are public.
                                // Authentication is not required for registration and login.
                                .requestMatchers(
                                        "/users/register",
                                        "/users/login"
                                ).permitAll()

                                // The logged-in user can access their own profile.
                                // A valid JWT must be present.
                                .requestMatchers("/users/me")
                                .authenticated()

                                // Only users with the ADMIN role can access
                                // these user-management endpoints.
                                .requestMatchers(
                                        "/users",
                                        "/users/{id}"
                                ).hasRole("ADMIN")

                                // Any other endpoint requires authentication.
                                .anyRequest().authenticated()
                )

                // Make the application stateless.
                // Spring Security will NOT maintain authentication using
                // an HTTP session. Each request must carry its JWT.
                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS
                        )
                )

                // If authentication fails or the request does not contain
                // a valid authentication, use our custom 401 response.
                .exceptionHandling(ex ->
                        ex.authenticationEntryPoint(authenticationEntryPoint)
                )

                // Add our JwtFilter before Spring Security's
                // UsernamePasswordAuthenticationFilter.
                //
                // This allows our application to validate the JWT
                // and authenticate the user before authorization rules
                // are applied.
                .addFilterBefore(
                        jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class
                )

                // Build and return the Spring Security filter chain.
                .build();
    }


    @Bean
    public PasswordEncoder passwordEncoder() {

        // BCrypt is used to securely hash passwords.
        // We never store the user's plain-text password in the database.
        return new BCryptPasswordEncoder();
    }


    @Bean
    public AuthenticationManager authenticationManager(
            CustomUserService customUserService,
            PasswordEncoder passwordEncoder) {

        // DaoAuthenticationProvider performs username/password
        // authentication using UserDetailsService.
        DaoAuthenticationProvider daoAuthenticationProvider =
                new DaoAuthenticationProvider(customUserService);

        // Tell Spring Security to use BCrypt when comparing
        // the entered password with the password stored in the database.
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);

        // ProviderManager delegates authentication to the configured
        // AuthenticationProvider.
        return new ProviderManager(daoAuthenticationProvider);
    }


    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {

        // AuthenticationEntryPoint is called when a user tries to access
        // a protected endpoint without valid authentication.
        return (request, response, authException) -> {

            // Return HTTP 401 Unauthorized.
            response.setStatus(HttpStatus.UNAUTHORIZED.value());

            // Tell the client that the response body is JSON.
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            // Return a custom JSON error response.
            response.getWriter().write(
                    "{\"Status\":401," +
                            "\"error\":\"Unauthorized\"," +
                            "\"message\":\"Missing or Invalid bearer token\"}"
            );
        };
    }
}
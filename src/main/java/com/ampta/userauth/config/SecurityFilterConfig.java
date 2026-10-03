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

    /*
     * SecurityFilterChain defines how Spring Security should process
     * incoming HTTP requests.
     *
     * The flow is:
     *
     * Request
     *    ↓
     * JwtFilter
     *    ↓
     * JWT validation
     *    ↓
     * SecurityContext
     *    ↓
     * Authorization rules
     *    ↓
     * Controller
     */
    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity httpSecurity,
            JwtService jwtService,
            CustomUserService customUserService,
            AuthenticationEntryPoint authenticationEntryPoint) {

        /*
         * Create our custom JWT filter.
         *
         * JwtFilter reads the JWT from the Authorization header,
         * validates it, extracts the user's email, loads the user,
         * and places the authenticated user inside the SecurityContext.
         */
        JwtFilter jwtAuthenticationFilter =
                new JwtFilter(jwtService, customUserService);


        return httpSecurity

                /*
                 * Disable CSRF protection because this application is
                 * using stateless JWT authentication.
                 *
                 * With JWT authentication, the server does not maintain
                 * a login session for the user. Each request carries
                 * authentication information through the JWT.
                 */
                .csrf(csrf -> csrf.disable())


                /*
                 * Define authorization rules for application endpoints.
                 *
                 * Authentication and authorization are different:
                 *
                 * Authentication:
                 * "Who are you?"
                 *
                 * Authorization:
                 * "What are you allowed to access?"
                 */
                .authorizeHttpRequests(
                        request -> request

                                /*
                                 * Registration and login are public
                                 * endpoints.
                                 *
                                 * A user does not have a JWT yet when
                                 * registering or logging in, so these
                                 * endpoints must be accessible without
                                 * authentication.
                                 */
                                .requestMatchers(
                                        "/users/register",
                                        "/users/login"
                                ).permitAll()


                                /*
                                 * /users/me is accessible only to an
                                 * authenticated user.
                                 *
                                 * The JwtFilter must successfully validate
                                 * the JWT and place authentication information
                                 * into the SecurityContext.
                                 */
                                .requestMatchers("/users/me")
                                .authenticated()


                                /*
                                 * These are user-management endpoints.
                                 *
                                 * Only users having the ADMIN role are
                                 * allowed to access them.
                                 *
                                 * hasRole("ADMIN") internally expects the
                                 * authority:
                                 *
                                 * ROLE_ADMIN
                                 */
                                .requestMatchers(
                                        "/users",
                                        "/users/{id}"
                                ).hasRole("ADMIN")


                                /*
                                 * Any endpoint not explicitly defined above
                                 * requires authentication.
                                 *
                                 * Therefore, by default, the application
                                 * does not allow anonymous access.
                                 */
                                .anyRequest().authenticated()
                )


                /*
                 * Configure the application as stateless.
                 *
                 * STATELESS means Spring Security will not create or use
                 * an HTTP session to remember authentication.
                 *
                 * Therefore, every protected request must provide a valid
                 * JWT.
                 *
                 * Example:
                 *
                 * Request 1 → Bearer JWT
                 * Request 2 → Bearer JWT
                 * Request 3 → Bearer JWT
                 */
                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS
                        )
                )


                /*
                 * Configure what should happen when authentication fails.
                 *
                 * For example, if a user requests a protected endpoint
                 * without a valid JWT, Spring Security invokes the
                 * AuthenticationEntryPoint.
                 *
                 * Our custom AuthenticationEntryPoint returns HTTP 401
                 * with a JSON response.
                 */
                .exceptionHandling(ex ->
                        ex.authenticationEntryPoint(authenticationEntryPoint)
                )


                /*
                 * Register our JwtFilter before Spring Security's
                 * UsernamePasswordAuthenticationFilter.
                 *
                 * This is important because we want our JWT authentication
                 * to happen before Spring Security checks authorization.
                 *
                 * The flow becomes:
                 *
                 * Request
                 *    ↓
                 * JwtFilter
                 *    ↓
                 * JWT validated
                 *    ↓
                 * SecurityContext populated
                 *    ↓
                 * Authorization rules
                 */
                .addFilterBefore(
                        jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class
                )


                /*
                 * Build the complete Spring Security filter chain.
                 */
                .build();
    }


    /*
     * PasswordEncoder is responsible for hashing passwords.
     *
     * BCrypt is a one-way password hashing algorithm.
     *
     * The application should never store the user's plain-text password
     * in the database.
     *
     * Example:
     *
     * Password entered:
     * Prince@123
     *
     * Database:
     * $2a$10$......
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /*
     * AuthenticationManager is responsible for performing
     * username/password authentication.
     *
     * In this application, the AuthenticationManager uses
     * DaoAuthenticationProvider.
     *
     * The flow during login is:
     *
     * Login request
     *      ↓
     * AuthenticationManager
     *      ↓
     * DaoAuthenticationProvider
     *      ↓
     * CustomUserService
     *      ↓
     * Database
     *      ↓
     * BCrypt password comparison
     *      ↓
     * Authentication successful/failed
     */
    @Bean
    public AuthenticationManager authenticationManager(
            CustomUserService customUserService,
            PasswordEncoder passwordEncoder) {


        /*
         * DaoAuthenticationProvider connects Spring Security's
         * username/password authentication mechanism with our
         * UserDetailsService.
         *
         * CustomUserService loads the user from the database.
         */
        DaoAuthenticationProvider daoAuthenticationProvider =
                new DaoAuthenticationProvider(customUserService);


        /*
         * Tell the authentication provider to use BCrypt when comparing
         * the password entered by the user with the hashed password
         * stored in the database.
         *
         * BCrypt does not decrypt the stored password.
         * Instead, it hashes the entered password and compares the result.
         */
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);


        /*
         * ProviderManager is an implementation of AuthenticationManager.
         *
         * It delegates the authentication request to the configured
         * AuthenticationProvider.
         */
        return new ProviderManager(daoAuthenticationProvider);
    }


    /*
     * AuthenticationEntryPoint handles authentication failures.
     *
     * It is used when a user tries to access a protected resource
     * without valid authentication.
     *
     * Example:
     *
     * GET /users/me
     *
     * Authorization header is missing or JWT is invalid.
     *
     * Spring Security calls this AuthenticationEntryPoint.
     */
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {

        return (request, response, authException) -> {


            /*
             * Return HTTP 401 Unauthorized.
             *
             * 401 means the request does not contain valid authentication
             * credentials.
             */
            response.setStatus(HttpStatus.UNAUTHORIZED.value());


            /*
             * Tell the client that the response body is JSON.
             */
            response.setContentType(
                    MediaType.APPLICATION_JSON_VALUE
            );


            /*
             * Send a custom JSON error response to the client.
             *
             * This prevents Spring Security from returning an unwanted
             * default HTML error page.
             */
            response.getWriter().write(
                    "{\"Status\":401," +
                            "\"error\":\"Unauthorized\"," +
                            "\"message\":\"Missing or Invalid bearer token\"}"
            );
        };
    }
}
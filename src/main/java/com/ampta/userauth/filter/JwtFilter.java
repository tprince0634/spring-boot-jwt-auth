package com.ampta.userauth.filter;

import com.ampta.userauth.service.CustomUserService;
import com.ampta.userauth.service.JwtService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    // Every JWT sent in the Authorization header should start with "Bearer "
    private static final String BEARER_PREFIX = "Bearer ";

    // Service responsible for JWT operations
    private final JwtService jwtService;

    private final CustomUserService customUserService;


    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        log.debug("JWT Filter processing request: {} {}",
                request.getMethod(),
                request.getRequestURI());

        // Get the Authorization header from the incoming HTTP request.
        // Authorization: Bearer eyJhbGciOiJIUzI1Ni...
        String header = request.getHeader("Authorization");


        // Check three things:
        // 1. header == null
        //    → No Authorization header was sent.
        //
        // 2. !header.startsWith(BEARER_PREFIX)
        //    → The Authorization header does not contain a Bearer JWT.
        //
        // 3. getAuthentication() != null
        //    → The user is already authenticated, so don't authenticate again.
        //
        // If any condition is true, skip JWT processing and continue
        // with the next filter.
        if (header == null
                || !header.startsWith(BEARER_PREFIX)
                || SecurityContextHolder.getContext().getAuthentication() != null) {

            log.debug("JWT authentication skipped for request: {} {}",
                    request.getMethod(),
                    request.getRequestURI());

            // Pass the request and response to the next filter.
            filterChain.doFilter(request, response);

            // Stop executing this filter.
            return;
        }


        try {

            // Remove "Bearer " from the Authorization header.
            //
            // Example:
            //
            // Header:
            // Bearer eyJhbGciOiJIUzI1Ni...
            //
            // After substring():
            // eyJhbGciOiJIUzI1Ni...
            String token = header.substring(BEARER_PREFIX.length());

            log.debug("Bearer token received for request: {} {}",
                    request.getMethod(),
                    request.getRequestURI());


            // Extract the subject from the JWT.
            //
            // In this application, the subject is being used as
            // the user's email/username.
            // Example:
            //
            // JWT subject → admin@gmail.com
            String email = jwtService.extractSubject(token);

            log.debug("JWT subject/email extracted: {}", email);


            // Use the email extracted from the JWT to load the user.
            //
            // CustomUserService normally searches the database and
            // returns a UserDetails object containing user information
            // and authorities/roles.
            UserDetails userDetails =
                    customUserService.loadUserByUsername(email);

            log.debug("User loaded successfully: {}", email);

            log.debug("User authorities: {}",
                    userDetails.getAuthorities());


            // Create an Authentication object representing the
            // authenticated user.
            //
            // userDetails
            //     → information about the current user
            //
            // null
            //     → credentials are not stored here because the JWT
            //       has already been used for authentication
            //
            // userDetails.getAuthorities()
            //     → user's roles/permissions
            //
            // Example:
            // ROLE_ADMIN
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,                  // 1. Who is the user?
                            null,                         // 2. Credentials
                            userDetails.getAuthorities()  // 3. What can the user do?
                    );


            // Attach information about the current HTTP request
            // to the Authentication object.
            //
            // This can contain details such as the remote IP address
            // and other request-related information.
            authentication.setDetails(
                    new WebAuthenticationDetailsSource()
                            .buildDetails(request)
            );


            // Create an empty SecurityContext.
            //
            // SecurityContext is used by Spring Security to hold
            // information about the authenticated user.
            SecurityContext securityContext =
                    SecurityContextHolder.createEmptyContext();

            // Think of SecurityContext as a container/box that Spring Security uses to hold authentication information.

            // Put the Authentication object into the SecurityContext.
            // Now Spring Security knows:
            // Who is the user?
            // What authorities/roles does the user have?
            securityContext.setAuthentication(authentication);


            // Store the SecurityContext for the current request.
            // From this point onward, other Spring Security filters
            // can access the authenticated user.
            SecurityContextHolder.setContext(securityContext);

            log.info("JWT authentication successful for user: {}", email);


        } catch (
            // JWT is invalid, expired, malformed, etc.
                JwtException
                // Invalid argument was supplied.
                | IllegalArgumentException

                // User could not be found in the database.
                | UsernameNotFoundException exception) {

            log.error(
                    "JWT authentication failed for request: {} {}",
                    request.getMethod(),
                    request.getRequestURI(),
                    exception
            );

            // Remove any authentication from the SecurityContext.
            //
            // The request will therefore not be considered authenticated.
            SecurityContextHolder.clearContext();
        }


        // Continue the request through the remaining Spring Security
        // filters and eventually to the controller if authorization
        // succeeds.
        filterChain.doFilter(request, response);
    }
}
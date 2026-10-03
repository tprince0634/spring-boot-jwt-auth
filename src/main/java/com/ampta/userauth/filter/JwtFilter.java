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

    /*
     * Every JWT request is expected to contain the token in the
     * Authorization HTTP header using the Bearer authentication scheme.
     *
     * Example:
     * Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
     */
    private static final String BEARER_PREFIX = "Bearer ";

    /*
     * JwtService is responsible for JWT-related operations such as
     * extracting claims and validating the JWT.
     */
    private final JwtService jwtService;

    /*
     * CustomUserService loads the user's information from the database
     * using the username/email extracted from the JWT.
     */
    private final CustomUserService customUserService;


    /*
     * This method is executed once for every HTTP request that passes
     * through this filter.
     *
     * The main responsibility of this filter is to:
     *
     * 1. Read the JWT from the Authorization header.
     * 2. Extract the username/email from the JWT.
     * 3. Load the user from the database.
     * 4. Create an Authentication object.
     * 5. Store that Authentication inside the SecurityContext.
     *
     * Once the SecurityContext contains authentication information,
     * the remaining Spring Security filters and controllers can
     * identify the current user.
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        log.debug(
                "JWT Filter processing request: {} {}",
                request.getMethod(),
                request.getRequestURI()
        );


        /*
         * Read the Authorization HTTP header from the incoming request.
         *
         * Example:
         *
         * Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
         *
         * The variable 'header' therefore contains the complete value:
         *
         * Bearer <FULL_JWT>
         *
         * It does NOT contain only the JWT Header section.
         */
        String header = request.getHeader("Authorization");


        /*
         * JWT processing is skipped when:
         *
         * 1. No Authorization header was provided.
         * 2. The Authorization header does not start with "Bearer ".
         * 3. The current request already has an authenticated user.
         *
         * In these cases, we simply allow the request to continue
         * through the remaining filters.
         */
        if (header == null
                || !header.startsWith(BEARER_PREFIX)
                || SecurityContextHolder.getContext().getAuthentication() != null) {

            log.debug(
                    "JWT authentication skipped for request: {} {}",
                    request.getMethod(),
                    request.getRequestURI()
            );

            filterChain.doFilter(request, response);
            return;
        }


        try {

            /*
             * Remove the "Bearer " prefix from the Authorization header.
             *
             * Before:
             *
             * Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOi...
             *
             * After:
             *
             * eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOi...
             *
             * The 'token' variable now contains the complete JWT:
             *
             * JWT = Header.Payload.Signature
             */
            String token = header.substring(BEARER_PREFIX.length());

            log.debug(
                    "Bearer token received for request: {} {}",
                    request.getMethod(),
                    request.getRequestURI()
            );


            /*
             * Extract the subject from the JWT.
             *
             * In this application, the JWT subject contains the user's
             * email address.
             *
             * Example JWT payload:
             *
             * {
             *     "sub": "prince@gmail.com",
             *     "role": "USER",
             *     "iat": ...,
             *     "exp": ...
             * }
             *
             * jwtService.extractSubject(token) parses the JWT and
             * returns the value of the 'sub' claim.
             */
            String email = jwtService.extractSubject(token);

            log.debug("JWT subject/email extracted: {}", email);


            /*
             * Now that we know the user's email from the JWT, we load
             * the corresponding user from the database.
             *
             * CustomUserService returns a UserDetails object containing
             * the user's information and authorities/roles.
             *
             * Example:
             *
             * email -> prince@gmail.com
             *              ↓
             *        Database lookup
             *              ↓
             *        UserDetails
             */
            UserDetails userDetails =
                    customUserService.loadUserByUsername(email);

            log.debug("User loaded successfully: {}", email);

            log.debug(
                    "User authorities: {}",
                    userDetails.getAuthorities()
            );


            /*
             * Create an Authentication object representing the user.
             *
             * UsernamePasswordAuthenticationToken has three important
             * values here:
             *
             * 1. userDetails
             *    Identifies the authenticated user.
             *
             * 2. null
             *    No password/credentials are stored because authentication
             *    has already been performed using the JWT.
             *
             * 3. userDetails.getAuthorities()
             *    Contains the user's roles/permissions.
             *
             * Example:
             *
             * UserDetails
             *      ↓
             * Authentication
             *      ↓
             * ROLE_USER
             */
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );


            /*
             * Attach additional information about the current HTTP request
             * to the Authentication object.
             *
             * Spring Security can use this information for request-related
             * details such as the remote IP address and session information.
             */
            authentication.setDetails(
                    new WebAuthenticationDetailsSource()
                            .buildDetails(request)
            );


            /*
             * Create a SecurityContext.
             *
             * SecurityContext acts as a container that stores information
             * about the currently authenticated user.
             */
            SecurityContext securityContext =
                    SecurityContextHolder.createEmptyContext();


            /*
             * Store the Authentication object inside the SecurityContext.
             *
             * At this point Spring Security knows:
             *
             * Who is the user?
             *      → userDetails
             *
             * What roles/authorities does the user have?
             *      → userDetails.getAuthorities()
             */
            securityContext.setAuthentication(authentication);


            /*
             * Store the SecurityContext in SecurityContextHolder.
             *
             * SecurityContextHolder makes the authentication information
             * available to the rest of the current request.
             *
             * Later, Spring Security can use this information for
             * authorization decisions such as:
             *
             * hasRole("ADMIN")
             * hasAuthority("READ_USERS")
             */
            SecurityContextHolder.setContext(securityContext);

            log.info(
                    "JWT authentication successful for user: {}",
                    email
            );


        } catch (
            /*
             * JwtException covers JWT-related problems such as:
             *
             * - Expired JWT
             * - Invalid signature
             * - Malformed JWT
             * - Invalid JWT structure
             */
                JwtException

                        /*
                         * Handles invalid or unexpected method arguments.
                         */
                | IllegalArgumentException

                        /*
                         * Handles the situation where the username/email extracted
                         * from the JWT does not exist in the database.
                         */
                | UsernameNotFoundException exception) {

            /*
             * Log the authentication failure.
             *
             * The exception is logged for debugging/production monitoring,
             * while the user should receive only an appropriate
             * authentication/authorization response rather than internal
             * technical details.
             */
            log.error(
                    "JWT authentication failed for request: {} {}",
                    request.getMethod(),
                    request.getRequestURI(),
                    exception
            );


            /*
             * Remove any authentication information from the current
             * SecurityContext.
             *
             * This ensures that an invalid or expired JWT does not leave
             * the request authenticated.
             */
            SecurityContextHolder.clearContext();
        }


        /*
         * Continue the request through the remaining filters.
         *
         * If authentication was successfully created, Spring Security
         * can use the SecurityContext for authorization.
         *
         * If JWT authentication failed, the SecurityContext is empty,
         * so protected endpoints can reject the request as unauthenticated.
         */
        filterChain.doFilter(request, response);
    }
}
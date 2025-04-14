package com.kurttekin.can.job_track.presentation.rest;

import java.util.Objects;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.mockito.ArgumentMatchers.any;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.kurttekin.can.job_track.application.dto.ErrorResponse;
import com.kurttekin.can.job_track.application.dto.JwtResponse;
import com.kurttekin.can.job_track.application.dto.LoginRequest;
import com.kurttekin.can.job_track.application.dto.UserRegistrationRequest;
import com.kurttekin.can.job_track.application.service.EmailService;
import com.kurttekin.can.job_track.domain.model.user.User;
import com.kurttekin.can.job_track.domain.service.UserService;
import com.kurttekin.can.job_track.infrastructure.security.jwt.JwtProvider;

class AuthControllerTest {

    @InjectMocks
    private AuthController authController;

    @Mock
    private UserService userService;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private EmailService emailService;

    @Mock
    private JwtProvider jwtProvider;

    @Mock
    private Authentication authentication;

    private LoginRequest loginRequest;
    private UserRegistrationRequest userRegistrationRequest;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        loginRequest = new LoginRequest("testuser", "testpassword");
        userRegistrationRequest = new UserRegistrationRequest("testuser", "testuser@test.com", "testpassword");
    }

    // === Login tests ===
    @Test
    public void testLogin_Success() {
        User user = new User();
        user.setVerified(true);

        when(userService.findUserByUsername(loginRequest.getUsername())).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
        when(jwtProvider.generateToken(authentication)).thenReturn("jwtToken");

        ResponseEntity<?> response = authController.login(loginRequest);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("jwtToken", ((JwtResponse) Objects.requireNonNull(response.getBody())).getToken());
    }

    @Test
    public void testLogin_InvalidCredentials() {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        ResponseEntity<?> response = authController.login(loginRequest);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("Invalid credentials", response.getBody());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testLogin_EmailNotVerified() {
        User user = new User();
        user.setEmail("test@test.com");
        user.setVerified(false);

        when(userService.findUserByUsername(loginRequest.getUsername())).thenReturn(Optional.of(user));
        ResponseEntity<?> response = authController.login(loginRequest);

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertEquals("Email not verified. Please verify your email before logging in.",
                ((ErrorResponse) Objects.requireNonNull(response.getBody())).getMessage());

        verify(jwtProvider, never()).generateToken(any(Authentication.class));
    }

    // === Register tests ===
    @Test
    public void testRegisterUser_Success() {
        doNothing().when(userService).registerUser(any(UserRegistrationRequest.class));
        doNothing().when(emailService).sendVerificationEmail(any(), any(), any());

        ResponseEntity<?> response = authController.registerUser(userRegistrationRequest);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("User registered successfully! Please verify your email before logging in.", response.getBody());
    }

    @Test
    public void testRegisterUser_EmailAlreadyExists() {
        doThrow(new RuntimeException("Email already exists"))
                .when(userService).registerUser(any(UserRegistrationRequest.class));

        ResponseEntity<?> response = authController.registerUser(userRegistrationRequest);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("Email already exists", response.getBody());
    }

    @Test
    public void testRegisterUser_Failure() {
        doThrow(new RuntimeException("Registration failed"))
                .when(userService).registerUser(any(UserRegistrationRequest.class));

        ResponseEntity<?> response = authController.registerUser(userRegistrationRequest);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("Registration failed", response.getBody());
    }
}

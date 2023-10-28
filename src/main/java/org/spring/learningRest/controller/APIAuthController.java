package org.spring.learningRest.controller;

import java.time.Instant;
import java.util.stream.Collectors;

import org.spring.learningRest.business.JwtResponse;
import org.spring.learningRest.business.LoginBody;
import org.spring.learningRest.entity.User;
import org.spring.learningRest.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin(origins = "*", methods = {RequestMethod.GET, RequestMethod.POST},
        allowedHeaders = {"Authorization", "Content-Type"})
@RequestMapping("/api/auth")
public class APIAuthController {

        @Autowired
        JwtEncoder jwtEncoder;

        @Autowired
        AuthenticationManager authenticationManager;

        @Autowired
        UserService userService;

        @PostMapping("/token")
        public ResponseEntity<JwtResponse> token(@RequestBody LoginBody loginBody) {
                Instant now = Instant.now();
                long expiry = 3600L;
                var username = loginBody.getUsername();
                var password = loginBody.getPassword();
                Authentication authentication = authenticationManager
                                .authenticate(new UsernamePasswordAuthenticationToken(username, password));
                String scope = authentication.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.joining(" "));

                JwtClaimsSet claims = JwtClaimsSet.builder()
                                .issuer("self")
                                .issuedAt(now)
                                .expiresAt(now.plusSeconds(expiry))
                                .subject(authentication.getName())
                                .claim("scope", scope)
                                .build();

                JwtResponse response = new JwtResponse(
                                jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue(),
                                authentication.getName(), authentication.getAuthorities().stream()
                                                .map(GrantedAuthority::getAuthority)
                                                .collect(Collectors.joining(" ")));

                return ResponseEntity.ok(response);
        }

        @PostMapping("/signup")
        public ResponseEntity<String> registerUser(@RequestBody User signUpRequest) {
                try {
                        if (userService.existsByName(signUpRequest.getName())) {
                                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username already exists");
                        }
                        User user = new User();
                        user.setName(signUpRequest.getName());
                        user.setPassword(signUpRequest.getPassword());
                        if (signUpRequest.getRole() == null) {
                                signUpRequest.setRole("USER");
                        }
                        user.setRole(signUpRequest.getRole());
                        userService.create(user);
                        return ResponseEntity.ok("User registered successfully");
                } catch (Exception e) {
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                        .body("Registration failed: " + e.getMessage());
                }
        }

}
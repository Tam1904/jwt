package com.example.demo.controllers;

import com.example.demo.service.JwtUserDetailsService;
import com.example.demo.utils.JwtRequestModel;
import com.example.demo.utils.JwtResponseModel;
import com.example.demo.utils.TokenManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/",produces = "application/json")
@CrossOrigin
public class JwtController {

    private final JwtUserDetailsService jwtUserDetailsService;

    private final AuthenticationManager authenticationManager;

    private final TokenManager tokenManager;

    @Autowired
    public JwtController(JwtUserDetailsService jwtUserDetailsService, AuthenticationManager authenticationManager, TokenManager tokenManager) {
        this.jwtUserDetailsService = jwtUserDetailsService;
        this.authenticationManager = authenticationManager;
        this.tokenManager = tokenManager;
    }

    @PostMapping(path= "/login",consumes = "application/json")
    public ResponseEntity<JwtResponseModel> createToken(@RequestBody JwtRequestModel request) throws Exception{
        try{
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(),request.getPassword())
            );
        } catch (DisabledException e){
            throw new Exception("USER_DISABLED",e);
        } catch (BadCredentialsException e){
            throw new Exception("INVALID_CREDENTIALS",e);
        }
        final UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(request.getUsername());
        final String jwtToken = tokenManager.generateJwtToken(userDetails);
        return ResponseEntity.ok(new JwtResponseModel(jwtToken));

    }

}

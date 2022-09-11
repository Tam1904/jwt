package com.example.demo.service;

import com.example.demo.entities.Role;
import com.example.demo.entities.User;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public JwtUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        List<GrantedAuthority> grants = new ArrayList<>();
        if (user != null) {
            for (Role role : user.getRoles()) {
                SimpleGrantedAuthority grant = new SimpleGrantedAuthority(role.getRole());
                grants.add(grant);
            }
            UserDetails userDetails = new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), grants);
            return userDetails;
        }
        else {
            new UsernameNotFoundException("Fail");
        }
        return null;
    }
}

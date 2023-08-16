package com.example.springsecuritydemo.dao;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;


@Repository
public class UserDao {
    private final List<UserDetails> APPLICATION_USERS = Arrays.asList(
        new User("ddmyazz@gmail.com", "12345", Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN"))),
        new User("moi@gmail.com", "12345", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))),
        new User("teach@tech.com", "12345", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")))
    );
    

    public UserDetails findUserByEmail(String email) throws UsernameNotFoundException {
        // System.out.println("Email: " + email);

        return APPLICATION_USERS
        .stream()
        .filter(u -> u.getUsername().equalsIgnoreCase(email))
        .findFirst()
        .orElseThrow(() -> new UsernameNotFoundException("NO user was found!"));
    }
}

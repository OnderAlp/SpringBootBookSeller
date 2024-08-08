package com.sha.spring_boot_book_seller.security;

import com.sha.spring_boot_book_seller.controller.AuthenticationController;
import com.sha.spring_boot_book_seller.model.User;
import com.sha.spring_boot_book_seller.service.IUserService;
import com.sha.spring_boot_book_seller.util.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class CustomUserDetailsService implements UserDetailsService
{
    @Autowired
    private IUserService userService;

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        logger.error("Custom User Details Service 1");
        User user = userService.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));

        logger.error("Custom User Details Service 2");
        Set<GrantedAuthority> authorities = Set.of(SecurityUtils.convertToAuthority(user.getRole().name()));

        logger.error("Custom User Details Service 3");
        return UserPrincipal.builder()
                .user(user)
                .id(user.getId())
                .username(username)
                .password(user.getPassword())
                .authorities(authorities)
                .build();
    }
}

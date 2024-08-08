package com.sha.spring_boot_book_seller.service;

import com.sha.spring_boot_book_seller.model.User;
import com.sha.spring_boot_book_seller.security.UserPrincipal;
import com.sha.spring_boot_book_seller.security.jwt.IJwtProvider;
import com.sha.spring_boot_book_seller.security.jwt.JwtProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService implements IAuthenticationService
{
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private IJwtProvider jwtProvider;

    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);


    @Override
    public User signInAndReturnJWT(User signInRequest)
    {
        Authentication authentication = null;

        logger.error("AS 1");
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(signInRequest.getUsername(), signInRequest.getPassword())
            );
        }catch (Exception e) {
            logger.error("AS 1 PATLADI");
            logger.error(e.getMessage());
        }

        logger.error("AS 2:");

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        logger.error("AS 3:");

        String jwt = jwtProvider.generateToken(userPrincipal);

        logger.error("AS 4:");

        logger.error(jwt);

        User signInUser = userPrincipal.getUser();

        logger.error("AS 5:");

        signInUser.setToken(jwt);

        logger.error("AS 6:");

        logger.error(signInUser.toString());

        logger.error("AS 7:");

        return signInUser;
    }
}

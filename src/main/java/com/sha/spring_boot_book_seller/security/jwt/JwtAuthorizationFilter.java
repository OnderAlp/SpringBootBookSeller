package com.sha.spring_boot_book_seller.security.jwt;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import java.io.IOException;

public class JwtAuthorizationFilter extends OncePerRequestFilter
{
    @Autowired
    private IJwtProvider jwtProvider;

    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request)
    {
        return request.getRequestURI().startsWith("/api/internal");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException
    {
        final String authHeader = request.getHeader("Authorization");

        Authentication authentication = null;
        try{
            logger.error("JWT Auth Filter 1");
            authentication = jwtProvider.getAuthentication(request);
        }catch (Exception e)
        {
            logger.error(e.getMessage());
        }

        try{
            logger.error("JWT Auth Filter 2");
            if (authentication != null && jwtProvider.validateToken(request))
            {
                logger.error("JWT Auth Filter 2.5");
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }catch (Exception e)
        {
            logger.error(e.getMessage());
        }

        filterChain.doFilter(request,response);

    }

}

package com.sub.app.securityconfig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class UserAuthenticationProvider  extends AbstractUserDetailsAuthenticationProvider {
	
	@Autowired
	private CustomUserDetailsService customUserDetailsService;

	@Override
	protected void additionalAuthenticationChecks(UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
		
		if (authentication.getCredentials() == null || userDetails.getPassword() == null) {
			throw new BadCredentialsException("Credentials cannot be null");
		}
		
		if(authentication.getCredentials()!=null) {
			if(!authentication.getCredentials().equals(userDetails.getPassword())) {
				throw new BadCredentialsException("Bad credentials");
			}
		}
	}

	@Override
	protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		
		return customUserDetailsService.loadUserByUsername(username);
	}

}

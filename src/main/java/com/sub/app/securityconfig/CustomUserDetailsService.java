package com.sub.app.securityconfig;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.sub.app.domain.UserDetails;
import com.sub.app.model.UserModel;
import com.sub.app.repository.UserDetailsRepositorty;

@Component
public class CustomUserDetailsService implements UserDetailsService {
	
	@Autowired
	private UserDetailsRepositorty userDetailsRepositorty; 

	@Override
	public UserModel loadUserByUsername(String userName) throws UsernameNotFoundException {
		UserDetails user = userDetailsRepositorty.findByUserName(userName);
		if (user == null) {
			throw new UsernameNotFoundException("Username not found"); 
		}
		Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
		grantedAuthorities.add(new SimpleGrantedAuthority("USER"));
		
		return new UserModel(user.getUserName(), user.getPassword(), user.isEnabled(), !user.isExpired(), !user.isCredentialexpired(), !user.isLocked(), grantedAuthorities, user.getUserId());
	}

}

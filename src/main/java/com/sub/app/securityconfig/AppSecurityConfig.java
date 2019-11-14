package com.sub.app.securityconfig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class AppSecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private  UserAuthenticationProvider userAuthenticationProvider;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		//auth.inMemoryAuthentication().withUser("admin").password("admin").roles("USER");
		auth.authenticationProvider(userAuthenticationProvider);
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers("/login")
		.permitAll()
		.anyRequest()
		.authenticated()
		.and().formLogin().loginPage("/login").successForwardUrl("/home");
		
		http.csrf().disable();
		
		http.logout()
		.logoutUrl("/logout")
		.invalidateHttpSession(true)
		.deleteCookies("JSESSIONID").logoutSuccessUrl("/login");
	}
	
}

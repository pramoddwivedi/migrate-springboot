/**
 * 
 */
package com.dineshonjava.sbsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author Dinesh.Rajput
 *
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests(requests -> requests
						.requestMatchers("/", "/home", "/public/**", "/login").permitAll()
						.requestMatchers("/users/**").hasAuthority("ADMIN")
						.anyRequest().fullyAuthenticated())
				.formLogin(login -> login
						.loginPage("/login")
						.failureUrl("/login?error")
						.usernameParameter("email")
						.permitAll())
				.logout(logout -> logout
						.logoutUrl("/logout")
						.logoutSuccessUrl("/")
						.permitAll());
    }

    /*~~(Migrate manually based on https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter)~~>*/@Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(userDetailsService)
                .passwordEncoder(new BCryptPasswordEncoder());
    }
}

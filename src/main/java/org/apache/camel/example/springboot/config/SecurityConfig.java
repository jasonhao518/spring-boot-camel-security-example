package org.apache.camel.example.springboot.config;

import java.util.Arrays;

import org.apache.camel.component.spring.security.SpringSecurityAccessPolicy;
import org.apache.camel.component.spring.security.SpringSecurityAuthorizationPolicy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

	@Bean
	public SecurityFilterChain securitygWebFilterChain(HttpSecurity http) throws Exception {
		return http.csrf().disable().anonymous().disable().authorizeRequests().anyRequest().authenticated().and().httpBasic().and().build();

	}

	@Bean
	public UserDetailsService users() {
		UserDetails user = User.builder().username("user")
				.password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW").roles("USER").build();
		UserDetails admin = User.builder().username("admin")
				.password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW").roles("USER", "ADMIN")
				.build();
		return new InMemoryUserDetailsManager(user, admin);
	}

	@Bean
	public AuthenticationManager authenticationManager() {
		DaoAuthenticationProvider dao = new DaoAuthenticationProvider();
		dao.setUserDetailsService(users());
		return new ProviderManager(dao);
	}

	@Bean
	public AccessDecisionManager accessDecisionManager() {
		return new AffirmativeBased(Arrays.asList(new RoleVoter()));
	}

	@Bean
	public SpringSecurityAuthorizationPolicy adminPolicy() {
		SpringSecurityAuthorizationPolicy policy = new SpringSecurityAuthorizationPolicy();
		policy.setId("adminPolicy");
		policy.setAccessDecisionManager(accessDecisionManager());
		policy.setAuthenticationManager(authenticationManager());
		policy.setSpringSecurityAccessPolicy(new SpringSecurityAccessPolicy("ROLE_ADMIN"));
		return policy;
	}

}

package br.com.grokhong.springjwt.security;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
        .csrf().disable()
        // .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        // .and()
        .authorizeRequests()
        .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
        .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
        .anyRequest().authenticated().and().formLogin()
        .loginPage("/login").permitAll()
        .defaultSuccessUrl("/courses",true)
        .and()
        .rememberMe() // defaults to 2 weeks
            .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
            .key("somethingverysecured");
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails pauloUser = User.builder().username("paulo").password(passwordEncoder.encode("password"))
                // .roles(ApplicationUserRole.STUDENT.name())
                .authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
                .build(); // ROLE_STUDENT

        UserDetails pedroUser = User.builder().username("pedro").password(passwordEncoder.encode("password"))
                // .roles(ApplicationUserRole.ADMIN.name())
                .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
                .build(); // ROLE ADMIN

        UserDetails lucasUser = User.builder().username("lucas").password(passwordEncoder.encode("password"))
                // .roles(ApplicationUserRole.ADMINTRAINEE.name())
                .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
                .build(); // ROLE ADMINTRAINEE

        return new InMemoryUserDetailsManager(pauloUser, pedroUser, lucasUser);
    }
}

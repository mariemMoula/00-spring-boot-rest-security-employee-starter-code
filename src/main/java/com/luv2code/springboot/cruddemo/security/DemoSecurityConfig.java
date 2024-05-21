package com.luv2code.springboot.cruddemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.net.http.HttpRequest;

@Configuration
public class DemoSecurityConfig {
    // add support for JDBC ... no more hardCoded users ...
//    @Bean
    // if we re using the schema given by spring
//    public UserDetailsManager userDetailsManager(DataSource dataSource){
//        // tells spring security to use JDBC authentication with our data source
//        return new JdbcUserDetailsManager(dataSource);
//    }
    // if we want to customize the tables
    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource) {
        JdbcUserDetailsManager jbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        // define query to retrieve a user by username
        jbcUserDetailsManager.setUsersByUsernameQuery(
                "select user_id,pw,active from members where user_id=?");
        // define query to retrieve roles by username
        jbcUserDetailsManager.setAuthoritiesByUsernameQuery(
                "select user_id, role from roles where user_id=?");

        return jbcUserDetailsManager;
    }


    // Restricting adds based on roles
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(configurer ->
                configurer
                        .requestMatchers(HttpMethod.GET, "/api/employees").hasAnyRole("EMPLOYEE")
                        .requestMatchers(HttpMethod.GET, "/api/employees/**").hasAnyRole("EMPLOYEE")
                        .requestMatchers(HttpMethod.PUT, "/api/employees").hasAnyRole("MANAGER")
                        .requestMatchers(HttpMethod.POST, "/api/employees").hasAnyRole("MANAGER")
                        .requestMatchers(HttpMethod.DELETE, "/api/employees/**").hasAnyRole("ADMIN")
        );
        // use HTTP Basic authentication
        http.httpBasic(Customizer.withDefaults());
        // disable Cross Site Forgery (CSRF)
        // in general , not required for stateless  REST APU  use POST , PUT , DELETE and/or PATCH
        http.csrf(csrf -> csrf.disable());
        // returning result
        return http.build();
    }
     /*
    @Bean
    public InMemoryUserDetailsManager userDetailsManager(){
        UserDetails jhon = User.builder()
                .username("Jhon")
                .password("{noop}test123")
                .roles("EMPLOYEE")
                .build();
        UserDetails yury = User.builder()
                .username("Mary")
                .password("{noop}test123")
                .roles("EMPLOYEE","MANAGER")
                .build();
        UserDetails susan = User.builder()
                .username("Susan")
                .password("{noop}test123")
                .roles("EMPLOYEE","MANAGER","ADMIN")
                .build();
        return new InMemoryUserDetailsManager(jhon,yury,susan);
    }
    */

}

package io.sumeet.springsecurityjdbc;

import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

// WebSecurityConfigurerAdapter : this class has the configure method

//Below Annotation tells spring security that this is a web security configuration.
// web security is just one of the ways in which we can configure security, the other ways are application/method level security
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

//    way to tell security where and how database is structured
    @Autowired
    DataSource dataSource;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // SET YOUR CONFIGURATION ON THE AUTH OBJECT

//        auth.jdbcAuthentication()
////                BELOW METHOD AUTOMATICALLY POINTS TO THE DATABASE USED IN THE CLASSPATH
//                .dataSource(dataSource)
////                BELOW MTHD CREATES SOME DEFAULT TABLES IN THE SCHEMA LIKE USERS TABLES AND AUTHORITIES TABLES.
//                .withDefaultSchema()
//                .withUser(
//                        User.withUsername("user")
//                        .password("pass")
//                        .roles("USER")
//                )
//                .withUser(
//                        User.withUsername("admin")
//                                .password("pass")
//                                .roles("ADMIN")
//                );
//-----------------------------------------------------------------------------------------------------
//        IF WE WANT TO MANUALLY CREATE OUR OWN SCHEMA, WE CAN CREATE SCHEMA.SQL FILE AND DATA.SQL FILE
//        TO TELL SPRING SECURITY TO USE THE DATA FROM THERE

//        auth.jdbcAuthentication()
//                        .dataSource(dataSource);

//-----------------------------------------------------------------------------------------------------
//        IF WE WANT TO SPECIFY OUR OWN CUSTOM USER AND AUTHORITIES TABLES LIKE MY_USER TABLES OR SOMETHING, WE CAN
//        SPECIFY THAT USING BELOW CODE WHERE IN PLACE OF USERS TABLES MY CUSTOM TABLE NAME WILL BE THERE LIKE
//        MY_USER AND MY_AUTHORITIES.

//        ALSO, IF WE HAVE AN EXTERNAL DATABASE, WE CONFIGURE IT IN application.properties
        auth.jdbcAuthentication()
                .dataSource(dataSource)
                .usersByUsernameQuery("select username,password,enabled "
                            +"from users where username = ?")
                .authoritiesByUsernameQuery("select username,authority "
                            +"from authorities where username = ?");

    }
//  SPRING SECURITY SAYS THAT IT IS NOT GOING TO ASSUME THAT THE PASSWORDS ARE CLEAR TEXT.
//    IT IS GOING TO ENCODE PASSWORDS AND IS GOING TO ENFORCE DEVELOPERS TO DO PASSWORD ENCODING
    @Bean
    public PasswordEncoder getPasswordEncoder(){
//      NOOPPASSWORDENCODER RETURNS NOTHING.
        return NoOpPasswordEncoder.getInstance();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

//        BELOW LOGIC TELLS SPRING SECURITY THAT ALL URLS SHOULD HAVE ROLE OF A USER
        //        http.authorizeRequests()
//                .antMatchers("/**").hasRole("USER")

//       FORMLOGIN() - THE TYPE OF LOGIN USER WANTS
//        ANTMATCHER IS USED TO SPECIFY THE PATH
//        USING HASANYROLE, WE CAN PASS MORE THAN ONE ROLES

//                / URL IS PERMITTED FOR EVERYONE SINCE IT IS ROOT URL
//        http.authorizeRequests()
//                        .antMatchers("/").permitAll()
//                        .antMatchers("/**").hasAnyRole("ADMIN")
//                        .and().formLogin();

//        WE SHOULD PUT MOST RESTRICTIVE AT THE TOP AND SO ON IN DECREASING ORDER
        http.authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/user").hasAnyRole("USER","ADMIN")
                .antMatchers("/").permitAll()
                .and().formLogin();
    }
}

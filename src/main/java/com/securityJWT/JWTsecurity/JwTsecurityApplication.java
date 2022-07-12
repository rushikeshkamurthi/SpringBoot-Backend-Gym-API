package com.securityJWT.JWTsecurity;

import com.securityJWT.JWTsecurity.DomainEntityModel.Role;
import com.securityJWT.JWTsecurity.DomainEntityModel.appUser;
import com.securityJWT.JWTsecurity.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
@SpringBootApplication
public class JwTsecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwTsecurityApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}
	@Bean
	CommandLineRunner run (UserService userService){
return args -> {
	userService.saveRole(new Role(1,"ROLE_USER"));
	userService.saveRole(new Role(2,"ROLE_MANAGER"));
	userService.saveRole(new Role(3,"ROLE_ADMIN"));
	userService.saveRole(new Role(4,"ROLE_SUPER_ADMIN"));
	userService.saveAppUser((new appUser(1,"admin","admin","abcd1", new ArrayList<>())));
	userService.saveAppUser((new appUser(2,"user","user","abcd2", new ArrayList<>())));
	userService.saveAppUser((new appUser(3,"editor","editor","abcd3", new ArrayList<>())));
	userService.saveAppUser((new appUser(4,"super","super","abcd4", new ArrayList<>())));

	userService.addRoleToUSer("admin","ROLE_ADMIN");
	userService.addRoleToUSer("user","ROLE_USER");
	userService.addRoleToUSer("editor","ROLE_MANAGER");
	userService.addRoleToUSer("super","ROLE_SUPER_ADMIN");
};

	}

}

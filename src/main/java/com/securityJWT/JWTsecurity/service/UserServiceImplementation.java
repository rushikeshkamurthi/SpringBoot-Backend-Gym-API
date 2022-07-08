package com.securityJWT.JWTsecurity.service;

import com.securityJWT.JWTsecurity.DomainEntityModel.Role;
import com.securityJWT.JWTsecurity.DomainEntityModel.appUser;
import com.securityJWT.JWTsecurity.Repository.RoleRepo;
import com.securityJWT.JWTsecurity.Repository.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
@Service @RequiredArgsConstructor @Transactional @Slf4j
public class UserServiceImplementation implements  UserService, UserDetailsService {
   private  final UserRepo userRepo;
    private  final RoleRepo roleRepo;
    private  final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        appUser user = userRepo.findByUsername(username);
        if(user == null)
        {
            log.error("User not found in the database");
            throw new UsernameNotFoundException("User not found in the database");
        }
        else
        {
            log.info("User fount  in the database:{}",user.getUsername());
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),authorities);
    }
    @Override
    public appUser saveAppUser(appUser user) {

        log.info("saving new user to data base") ;
        user.setPassword(passwordEncoder.encode(user.getPassword())); // encoding user password and saving
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saving ROLE to data base") ;
        return roleRepo.save(role) ;

    }

    @Override
    public void addRoleToUSer(String username, String roleName) {
        log.info("Adding {} role to user {} " ,roleName,username) ;
   appUser user=userRepo.findByUsername(username);
   Role role=roleRepo.findByName(roleName);
   user.getRoles().add(role); //  here each user has collection of roles , we are adding one more role item to that collection

    }

    @Override
    public appUser getAppUser(String username) {
        log.info("Fetching user {} ",username) ;
        return userRepo.findByUsername(username);
    }

    @Override
    public List<appUser> getAppUsers() {
        log.info("Fetching all user") ;
        return userRepo.findAll();
    }
}

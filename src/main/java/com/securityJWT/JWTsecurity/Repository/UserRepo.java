package com.securityJWT.JWTsecurity.Repository;


import com.securityJWT.JWTsecurity.DomainEntityModel.appUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<appUser,Long> {
    appUser findByUsername(String username);

}

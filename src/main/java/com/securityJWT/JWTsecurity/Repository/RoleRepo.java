package com.securityJWT.JWTsecurity.Repository;
import com.securityJWT.JWTsecurity.DomainEntityModel.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role,Long> {

    Role findByName(String name); // it  returns the Role if we provide name of the role


}

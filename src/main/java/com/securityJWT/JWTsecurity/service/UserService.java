package com.securityJWT.JWTsecurity.service;
import com.securityJWT.JWTsecurity.DomainEntityModel.Role;
import com.securityJWT.JWTsecurity.DomainEntityModel.appUser;

import java.util.List;

public interface UserService {

    appUser saveAppUser(appUser user);

    Role saveRole(Role role);

    void addRoleToUSer(String username,String roleName);

    appUser getAppUser(String username);

    List<appUser> getAppUsers(); // you can set see 10 user per page like system

}

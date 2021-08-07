package br.com.grokhong.springjwt.auth;

import java.util.List;
import java.util.Optional;

import com.google.common.collect.Lists;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import br.com.grokhong.springjwt.security.ApplicationUserRole;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getAplicationUsers().stream().filter(applicationUser -> username.equals(applicationUser.getUsername())).findFirst();
    }

    private List<ApplicationUser> getAplicationUsers() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser("paulo", passwordEncoder.encode("password"),
                        ApplicationUserRole.STUDENT.getGrantedAuthorities(), true, true, true, true),
                new ApplicationUser("pedro", passwordEncoder.encode("password"),
                        ApplicationUserRole.ADMIN.getGrantedAuthorities(), true, true, true, true),
                new ApplicationUser("lucas", passwordEncoder.encode("password"),
                        ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities(), true, true, true, true));

        return applicationUsers;
    }
}

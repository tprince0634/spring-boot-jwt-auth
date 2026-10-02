package com.ampta.userauth.repository;

import com.ampta.userauth.dto.UserResponse;
import com.ampta.userauth.entity.UserAuth;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserAuth, Long> {

    Optional<UserAuth> findByEmail(String email);
    List<UserAuth> findByRole(String role);

    Optional<UserAuth> findByEmailAndPassword(String email, String password);

    boolean existsByEmail(String email);
    boolean existsByUsername(String username);
}

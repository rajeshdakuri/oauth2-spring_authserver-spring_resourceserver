package com.example.authserver.repository;

import com.example.authserver.model.AuthRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<AuthRequest, String> {

    Optional<AuthRequest> findByEmail(String username);
}

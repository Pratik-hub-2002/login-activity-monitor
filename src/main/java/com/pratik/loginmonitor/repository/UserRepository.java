package com.pratik.loginmonitor.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.pratik.loginmonitor.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}

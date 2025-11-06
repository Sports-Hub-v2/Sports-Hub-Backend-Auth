package com.sportshub.auth.repository;

import com.sportshub.auth.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AccountRepository extends JpaRepository<Account, Long> {
    Optional<Account> findByEmail(String email);
    Optional<Account> findByUserid(String userid);
    Optional<Account> findByEmailOrUserid(String email, String userid);
}

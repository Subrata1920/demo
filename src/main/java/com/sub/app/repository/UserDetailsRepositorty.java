package com.sub.app.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.sub.app.domain.UserDetails;

public interface UserDetailsRepositorty extends JpaRepository<UserDetails, Integer> {

	UserDetails findByUserName(String userName);

}

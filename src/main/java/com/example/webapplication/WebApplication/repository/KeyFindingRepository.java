package com.example.webapplication.WebApplication.repository;

import com.example.webapplication.WebApplication.model.KeyFinding;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface KeyFindingRepository extends JpaRepository<KeyFinding, Long> {
}

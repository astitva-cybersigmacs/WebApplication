package com.example.webapplication.WebApplication.repository;

import com.example.webapplication.WebApplication.model.SummaryOfObservation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SummaryOfObservationRepository extends JpaRepository<SummaryOfObservation, Long> {
}

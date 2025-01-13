package com.example.webapplication.WebApplication.repository;

import com.example.webapplication.WebApplication.model.WebApplicationReport;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface WebApplicationReportRepository extends JpaRepository<WebApplicationReport, Long> {
    WebApplicationReport findByReportIdAndProjectId(long reportId, long projectId);
    WebApplicationReport findByReportId(long reportId);
}

package com.example.webapplication.WebApplication.service;

import com.example.webapplication.WebApplication.model.KeyFinding;
import com.example.webapplication.WebApplication.model.SummaryOfObservation;
import com.example.webapplication.WebApplication.model.VulnerabilityDetails;
import com.example.webapplication.WebApplication.model.WebApplicationReport;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface WebApplicationReportService {
    WebApplicationReport addOrUpdateReport(long reportId, WebApplicationReport webApplicationReport);

    WebApplicationReport addOrUpdateSummaryObservation(long reportId, WebApplicationReport webApplicationReport);

    WebApplicationReport addOrUpdateVulnerability(long projectId, String name, String summary, String remedy, List<String> remedyReference,String resourceAffected, String proofOfVulnerability, String proofOfVulnerabilityType, MultipartFile file);

    List<KeyFinding> getKeyFindingsByProjectId(long projectId);

    List<SummaryOfObservation> getSummaryObservationsByProjectId(long projectId);

    List<VulnerabilityDetails> getVulnerabilityDetailsByProjectId(long projectId);

    List<byte[]> getVulnerabilityImagesByProjectId(long projectId);
}

package com.example.webapplication.WebApplication.service;

import com.example.webapplication.WebApplication.model.KeyFinding;
import com.example.webapplication.WebApplication.model.SummaryOfObservation;
import com.example.webapplication.WebApplication.model.VulnerabilityDetails;
import com.example.webapplication.WebApplication.model.WebApplicationReport;
import com.example.webapplication.WebApplication.repository.WebApplicationReportRepository;
import com.example.webapplication.WebApplication.utils.FileUtils;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@AllArgsConstructor
@Service
public class WebApplicationReportServiceImpl implements WebApplicationReportService {


    private WebApplicationReportRepository webApplicationReportRepository;

    @Override
    @Transactional
    public WebApplicationReport addOrUpdateReport(long projectId, WebApplicationReport newReport) {
        // Find existing report
        WebApplicationReport existingReport = this.webApplicationReportRepository.findByProjectId(projectId);

        if (existingReport != null) {
            // Preserve the existing ID and projectId
            newReport.setWebApplicationReportId(existingReport.getWebApplicationReportId());
            newReport.setProjectId(projectId);

            // Update key findings
            if (newReport.getKeyFindingList() != null) {
                for (KeyFinding keyFinding : newReport.getKeyFindingList()) {
                    keyFinding.setWebApplicationReport(newReport);
                }
            }

            return this.webApplicationReportRepository.save(newReport);
        } else {
            // Create new report
            newReport.setProjectId(projectId);

            // Set up relationships for key findings
            if (newReport.getKeyFindingList() != null) {
                for (KeyFinding keyFinding : newReport.getKeyFindingList()) {
                    keyFinding.setWebApplicationReport(newReport);
                }
            }

            return this.webApplicationReportRepository.save(newReport);
        }
    }

    @Override
    @Transactional
    public WebApplicationReport addOrUpdateSummaryObservation(long projectId, WebApplicationReport newReport) {
        WebApplicationReport existingReport = this.webApplicationReportRepository.findByProjectId(projectId);
        if (existingReport == null) {
            throw new RuntimeException("Report not found for project id: " + projectId);
        }

        // Update summary observations
        if (newReport.getSummaryOfObservationList() != null) {
            existingReport.getSummaryOfObservationList().clear();
            for (SummaryOfObservation observation : newReport.getSummaryOfObservationList()) {
                observation.setWebApplicationReport(existingReport);
                existingReport.getSummaryOfObservationList().add(observation);
            }
        }

        return this.webApplicationReportRepository.save(existingReport);
    }

    @Override
    @Transactional
    public WebApplicationReport addOrUpdateVulnerability(long projectId, String name, String summary, String remedy,
                                                         List<String> remedyReference, String resourceAffected, String proofOfVulnerability,
                                                         String proofOfVulnerabilityType, MultipartFile file) {
        WebApplicationReport existingReport = this.webApplicationReportRepository.findByProjectId(projectId);
        if (existingReport == null) {
            throw new RuntimeException("Report not found for project id: " + projectId);
        }

        VulnerabilityDetails vulnerabilityDetails = new VulnerabilityDetails();
        vulnerabilityDetails.setName(name);
        vulnerabilityDetails.setSummary(summary);
        vulnerabilityDetails.setRemedy(remedy);
        vulnerabilityDetails.setResourceAffected(resourceAffected);
        vulnerabilityDetails.setProofOfVulnerability(proofOfVulnerability);
        vulnerabilityDetails.setProofOfVulnerabilityType(proofOfVulnerabilityType);
        vulnerabilityDetails.setRemedyReference(remedyReference);

        try {
            // Compress the file before saving it
            byte[] compressedFile = FileUtils.compressFile(file.getBytes());
            vulnerabilityDetails.setFile(compressedFile);
        } catch (IOException e) {
            throw new RuntimeException("Error uploading and compressing file: " + e.getMessage());
        }

        // Add vulnerability to the report
        vulnerabilityDetails.setWebApplicationReport(existingReport);
        existingReport.getVulnerabilityDetailsList().add(vulnerabilityDetails);

        return this.webApplicationReportRepository.save(existingReport);
    }

    @Override
    @Transactional
    public List<KeyFinding> getKeyFindingsByProjectId(long projectId) {
        WebApplicationReport existingReport = this.webApplicationReportRepository.findByProjectId(projectId);
        if (existingReport == null) {
            throw new RuntimeException("Report not found for project id: " + projectId);
        }
        return existingReport.getKeyFindingList();
    }

    @Override
    @Transactional
    public List<SummaryOfObservation> getSummaryObservationsByProjectId(long projectId) {
        WebApplicationReport existingReport = this.webApplicationReportRepository.findByProjectId(projectId);
        if (existingReport == null) {
            throw new RuntimeException("Report not found for project id: " + projectId);
        }
        return existingReport.getSummaryOfObservationList();
    }

    @Override
    @Transactional
    public List<VulnerabilityDetails> getVulnerabilityDetailsByProjectId(long projectId) {
        // Fetch the WebApplicationReport based on the projectId
        WebApplicationReport existingReport = this.webApplicationReportRepository.findByProjectId(projectId);

        if (existingReport == null) {
            throw new RuntimeException("Report not found for project id: " + projectId);
        }

        return existingReport.getVulnerabilityDetailsList();
    }

}

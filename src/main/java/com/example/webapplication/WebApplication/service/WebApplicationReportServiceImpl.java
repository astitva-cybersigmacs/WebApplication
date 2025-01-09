package com.example.webapplication.WebApplication.service;

import com.example.webapplication.WebApplication.model.KeyFinding;
import com.example.webapplication.WebApplication.model.SummaryOfObservation;
import com.example.webapplication.WebApplication.model.VulnerabilityDetails;
import com.example.webapplication.WebApplication.model.WebApplicationReport;
import com.example.webapplication.WebApplication.repository.KeyFindingRepository;
import com.example.webapplication.WebApplication.repository.SummaryOfObservationRepository;
import com.example.webapplication.WebApplication.repository.VulnerabilityDetailsRepository;
import com.example.webapplication.WebApplication.repository.WebApplicationReportRepository;
import com.example.webapplication.WebApplication.utils.FileUtils;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@AllArgsConstructor
@Service
public class WebApplicationReportServiceImpl implements WebApplicationReportService {


    private WebApplicationReportRepository webApplicationReportRepository;
    private KeyFindingRepository keyFindingRepository;
    private SummaryOfObservationRepository summaryOfObservationRepository;
    private VulnerabilityDetailsRepository vulnerabilityDetailsRepository;

    @Override
    @Transactional
    public WebApplicationReport addOrUpdateReport(long projectId, WebApplicationReport newReport) {
        // Find existing report
        WebApplicationReport existingReport = this.webApplicationReportRepository.findByProjectId(projectId);

        if (existingReport != null) {
            // Preserve the existing ID and projectId
            newReport.setWebApplicationReportId(existingReport.getWebApplicationReportId());
            newReport.setProjectId(projectId);

            // Delete old key findings before updating
            Set<Long> keyFindingIds = new HashSet<>();
            if (existingReport.getKeyFindingList() != null) {
                for (KeyFinding keyFinding : existingReport.getKeyFindingList()) {
                    keyFindingIds.add(keyFinding.getKeyFindingId());
                }
                this.keyFindingRepository.deleteAllByIdInBatch(keyFindingIds);
            }

            // Update relationships for new key findings
            if (newReport.getKeyFindingList() != null) {
                for (KeyFinding keyFinding : newReport.getKeyFindingList()) {
                    keyFinding.setWebApplicationReport(newReport);
                }
            }

            // Save and return the updated report
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

            // Save and return the new report
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

        // Delete old summary observations
        Set<Long> summaryObservationIds = new HashSet<>();
        if (existingReport.getSummaryOfObservationList() != null) {
            for (SummaryOfObservation observation : existingReport.getSummaryOfObservationList()) {
                summaryObservationIds.add(observation.getSummaryOfObservationId());
            }
            this.summaryOfObservationRepository.deleteAllByIdInBatch(summaryObservationIds);
        }

        // Update summary observations
        if (newReport.getSummaryOfObservationList() != null) {
            for (SummaryOfObservation observation : newReport.getSummaryOfObservationList()) {
                observation.setWebApplicationReport(existingReport);
            }
            existingReport.setSummaryOfObservationList(newReport.getSummaryOfObservationList());
        }

        return this.webApplicationReportRepository.save(existingReport);
    }


    @Override
    @Transactional
    public WebApplicationReport addOrUpdateVulnerability(long projectId, String name, String summary, String remedy,
                                                         List<String> remedyReference, String resourceAffected,
                                                         String proofOfVulnerability, String proofOfVulnerabilityType,
                                                         MultipartFile file) {
        WebApplicationReport existingReport = this.webApplicationReportRepository.findByProjectId(projectId);
        if (existingReport == null) {
            throw new RuntimeException("Report not found for project id: " + projectId);
        }

        // Delete old vulnerabilities
        Set<Long> vulnerabilityIds = new HashSet<>();
        if (existingReport.getVulnerabilityDetailsList() != null) {
            for (VulnerabilityDetails vulnerability : existingReport.getVulnerabilityDetailsList()) {
                vulnerabilityIds.add(vulnerability.getVulnerabilityDetailsId());
            }
            this.vulnerabilityDetailsRepository.deleteAllByIdInBatch(vulnerabilityIds);
        }

        // Create new vulnerability details
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

        // Associate the new vulnerability with the report
        vulnerabilityDetails.setWebApplicationReport(existingReport);
        existingReport.getVulnerabilityDetailsList().clear(); // Clear the old list
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

package com.example.webapplication.WebApplication.service;

import com.example.webapplication.WebApplication.model.*;
import com.example.webapplication.WebApplication.repository.*;
import com.example.webapplication.WebApplication.utils.FileUtils;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.ArrayList;
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
    private VulnerabilityDetailsImagesRepository vulnerabilityDetailsImagesRepository;

    @Override
    @Transactional
    public WebApplicationReport addOrUpdateReport(long reportId, WebApplicationReport newReport) {
        // Find existing report using both reportId and projectId
        WebApplicationReport existingReport = this.webApplicationReportRepository
                .findByReportIdAndProjectId(reportId, newReport.getProjectId());

        if (existingReport != null) {
            // Preserve the existing ID and reportId
            newReport.setWebApplicationReportId(existingReport.getWebApplicationReportId());
            newReport.setReportId(reportId);
            // No need to set projectId as it's already correct in newReport

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
            newReport.setReportId(reportId);

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
    public WebApplicationReport addOrUpdateSummaryObservation(long reportId, WebApplicationReport newReport) {
        // Find existing report using both reportId and projectId
        WebApplicationReport existingReport = this.webApplicationReportRepository
                .findByReportIdAndProjectId(reportId, newReport.getProjectId());

        if (existingReport != null) {
            // Preserve the existing IDs
            newReport.setWebApplicationReportId(existingReport.getWebApplicationReportId());
            newReport.setReportId(reportId);
            newReport.setProjectId(existingReport.getProjectId());

            // Delete old summary observations before updating
            Set<Long> summaryObservationIds = new HashSet<>();
            if (existingReport.getSummaryOfObservationList() != null) {
                for (SummaryOfObservation observation : existingReport.getSummaryOfObservationList()) {
                    summaryObservationIds.add(observation.getSummaryOfObservationId());
                }
                this.summaryOfObservationRepository.deleteAllByIdInBatch(summaryObservationIds);
            }

            // Update relationships for new summary observations
            if (newReport.getSummaryOfObservationList() != null) {
                for (SummaryOfObservation observation : newReport.getSummaryOfObservationList()) {
                    observation.setWebApplicationReport(newReport);
                }
            }

            // Save and return the updated report
            return this.webApplicationReportRepository.save(newReport);
        } else {
            // Create new report
            newReport.setReportId(reportId);

            // Set up relationships for summary observations
            if (newReport.getSummaryOfObservationList() != null) {
                for (SummaryOfObservation observation : newReport.getSummaryOfObservationList()) {
                    observation.setWebApplicationReport(newReport);
                }
            }

            // Save and return the new report
            return this.webApplicationReportRepository.save(newReport);
        }
    }


    @Override
    @Transactional
    public WebApplicationReport addOrUpdateVulnerability(long reportId, long projectId, String name, String summary,
                                                         String remedy, List<String> remedyReference, String resourceAffected,
                                                         String proofOfVulnerability, String proofOfVulnerabilityType,
                                                         List<MultipartFile> files) {
        // Find existing report using both reportId and projectId
        WebApplicationReport existingReport = this.webApplicationReportRepository
                .findByReportIdAndProjectId(reportId, projectId);

        if (existingReport == null) {
            throw new RuntimeException("Report not found for report id: " + reportId + " and project id: " + projectId);
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
        vulnerabilityDetails.setRemedyReference(remedyReference);

        List<VulnerabilityDetailsImages> imagesList = new ArrayList<>();
        for (int i = 0; i < files.size(); i++) {
            VulnerabilityDetailsImages image = new VulnerabilityDetailsImages();
            try {
                byte[] compressedFile = FileUtils.compressFile(files.get(i).getBytes());
                image.setFile(compressedFile);
                image.setProofOfVulnerability(files.get(i).getName());
                image.setProofOfVulnerabilityType(files.get(i).getContentType());
                image.setVulnerabilityDetails(vulnerabilityDetails);
                imagesList.add(image);
            } catch (IOException e) {
                throw new RuntimeException("Error uploading and compressing file: " + e.getMessage());
            }
        }

        vulnerabilityDetails.setVulnerabilityDetailsImagesList(imagesList);
        vulnerabilityDetails.setWebApplicationReport(existingReport);


        existingReport.getVulnerabilityDetailsList().clear(); // Clear the old list
        existingReport.getVulnerabilityDetailsList().add(vulnerabilityDetails);

        return this.webApplicationReportRepository.save(existingReport);
    }

    @Override
    @Transactional
    public List<KeyFinding> getKeyFindings(long projectId, long reportId) {
        WebApplicationReport existingReport = this.webApplicationReportRepository
                .findByReportIdAndProjectId(reportId, projectId);

        if (existingReport == null) {
            throw new RuntimeException("Report not found for report id: " + reportId + " and project id: " + projectId);
        }
        return existingReport.getKeyFindingList();
    }

    @Override
    @Transactional
    public List<SummaryOfObservation> getSummaryObservations(long projectId, long reportId) {
        WebApplicationReport existingReport = this.webApplicationReportRepository
                .findByReportIdAndProjectId(reportId, projectId);

        if (existingReport == null) {
            throw new RuntimeException("Report not found for report id: " + reportId + " and project id: " + projectId);
        }
        return existingReport.getSummaryOfObservationList();
    }

    @Override
    @Transactional
    public List<VulnerabilityDetails> getVulnerabilityDetailsByProjectId(long projectId, long reportId) {
        // Fetch the WebApplicationReport based on the projectId
        WebApplicationReport existingReport = this.webApplicationReportRepository.findByReportIdAndProjectId(reportId, projectId);

        if (existingReport == null) {
            throw new RuntimeException("Report not found for project id: " + projectId);
        }

        return existingReport.getVulnerabilityDetailsList();
    }

    @Override
    @Transactional
    public byte[] getVulnerabilityImageById(long imageId) {
        VulnerabilityDetailsImages image = this.vulnerabilityDetailsImagesRepository.findByVulnerabilityDetailsImageId(imageId);
        if (image == null) {
            throw new RuntimeException("Image not found for id: " + imageId);
        }

        if (image.getFile() == null) {
            throw new RuntimeException("No file found for image id: " + imageId);
        }

        return FileUtils.decompressFile(image.getFile());
    }

}

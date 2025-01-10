package com.example.webapplication.WebApplication.controller;

import com.example.webapplication.WebApplication.model.KeyFinding;
import com.example.webapplication.WebApplication.model.SummaryOfObservation;
import com.example.webapplication.WebApplication.model.VulnerabilityDetails;
import com.example.webapplication.WebApplication.model.WebApplicationReport;
import com.example.webapplication.WebApplication.service.WebApplicationReportService;
import com.example.webapplication.WebApplication.utils.ResponseModel;
import lombok.AllArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("webApplication")
@AllArgsConstructor
public class WebApplicationReportController {


    private WebApplicationReportService webApplicationReportService;

    @PostMapping("/key-finding")
    public ResponseEntity<Object> addOrUpdateReport(@RequestBody WebApplicationReport webApplicationReport) {
        try {
            if (webApplicationReport.getReportId() == 0) {
                return ResponseModel.error("Report ID is required");
            }
            if (webApplicationReport.getProjectId() == 0) {
                return ResponseModel.error("Project ID is required");
            }
            this.webApplicationReportService.addOrUpdateReport(webApplicationReport.getReportId(), webApplicationReport);
            return ResponseModel.success("Report added successfully");
        } catch (Exception e) {
            return ResponseModel.error(e.getMessage());
        }
    }

    @PostMapping("/summary-observation")
    public ResponseEntity<Object> addOrUpdateSummaryObservation(@RequestBody WebApplicationReport webApplicationReport) {
        try {
            if (webApplicationReport.getReportId() == 0) {
                return ResponseModel.error("Report ID is required");
            }
            if (webApplicationReport.getProjectId() == 0) {
                return ResponseModel.error("Project ID is required");
            }
            this.webApplicationReportService.addOrUpdateSummaryObservation(webApplicationReport.getReportId(), webApplicationReport);
            return ResponseModel.success("Summary of observations added/updated successfully");
        } catch (Exception e) {
            return ResponseModel.error(e.getMessage());
        }
    }

    @PostMapping("/vulnerability")
    public ResponseEntity<Object> addOrUpdateVulnerability(
            @RequestParam("reportId") long reportId,
            @RequestParam("projectId") long projectId,
            @RequestParam("name") String name,
            @RequestParam("summary") String summary,
            @RequestParam("remedy") String remedy,
            @RequestParam("remedyReference") List<String> remedyReference,
            @RequestParam("resourceAffected") String resourceAffected,
            @RequestParam("proofOfVulnerability") String proofOfVulnerability,
            @RequestParam("proofOfVulnerabilityType") String proofOfVulnerabilityType,
            @RequestParam("file") MultipartFile file) {
        try {
            if (reportId == 0) {
                return ResponseModel.error("Report ID is required");
            }
            if (projectId == 0) {
                return ResponseModel.error("Project ID is required");
            }
            this.webApplicationReportService.addOrUpdateVulnerability(
                    reportId, projectId, name, summary, remedy, remedyReference, resourceAffected,
                    proofOfVulnerability, proofOfVulnerabilityType, file
            );
            return ResponseModel.success("Vulnerability details added/updated successfully");
        } catch (Exception e) {
            return ResponseModel.error(e.getMessage());
        }
    }

    @GetMapping("/key-finding/{projectId}/{reportId}")
    public ResponseEntity<Object> getKeyFindings(
            @PathVariable long projectId,
            @PathVariable long reportId) {
        try {
            if (projectId == 0) {
                return ResponseModel.error("Project ID is required");
            }
            if (reportId == 0) {
                return ResponseModel.error("Report ID is required");
            }
            List<KeyFinding> keyFindings = this.webApplicationReportService.getKeyFindings(projectId, reportId);
            return ResponseModel.success("Key findings fetched successfully", keyFindings);
        } catch (Exception e) {
            return ResponseModel.error(e.getMessage());
        }
    }

    @GetMapping("/summary-observation/{projectId}/{reportId}")
    public ResponseEntity<Object> getSummaryObservations(
            @PathVariable long projectId,
            @PathVariable long reportId) {
        try {
            if (projectId == 0) {
                return ResponseModel.error("Project ID is required");
            }
            if (reportId == 0) {
                return ResponseModel.error("Report ID is required");
            }
            List<SummaryOfObservation> summaryObservations = this.webApplicationReportService.getSummaryObservations(projectId, reportId);
            return ResponseModel.success("Summary of observations fetched successfully", summaryObservations);
        } catch (Exception e) {
            return ResponseModel.error(e.getMessage());
        }
    }

    @GetMapping("/VulnerabilityDetails/{projectId}/{reportId}")
    public ResponseEntity<?> getVulnerabilityDetails(@PathVariable long projectId, @PathVariable long reportId) {
        try {
            if (projectId == 0) {
                return ResponseModel.error("Project ID is required");
            }
            if (reportId == 0) {
                return ResponseModel.error("Report ID is required");
            }
            // Fetch the vulnerability details by projectId
            List<VulnerabilityDetails> vulnerabilityDetailsList = this.webApplicationReportService.getVulnerabilityDetailsByProjectId(projectId, reportId);
            return ResponseEntity.ok(vulnerabilityDetailsList);
        } catch (Exception e) {
            return ResponseModel.error(e.getMessage());
        }
    }

    @GetMapping("/vulnerability/image/{projectId}/{index}")
    public ResponseEntity<byte[]> getVulnerabilityImageByIndex(
            @PathVariable long projectId,
            @PathVariable int index) {
        try {
            List<byte[]> images = this.webApplicationReportService.getVulnerabilityImagesByProjectId(projectId);

            if (images.isEmpty()) {
                throw new RuntimeException("No images found for project id: " + projectId);
            }

            if (index >= images.size()) {
                throw new RuntimeException("Image index out of bounds");
            }

            String contentType = "image/png";

            return ResponseEntity
                    .ok()
                    .contentType(MediaType.valueOf(contentType))
                    .body(images.get(index));
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }


}

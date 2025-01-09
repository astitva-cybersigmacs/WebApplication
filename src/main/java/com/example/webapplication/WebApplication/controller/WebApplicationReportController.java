package com.example.webapplication.WebApplication.controller;

import com.example.webapplication.WebApplication.model.KeyFinding;
import com.example.webapplication.WebApplication.model.SummaryOfObservation;
import com.example.webapplication.WebApplication.model.VulnerabilityDetails;
import com.example.webapplication.WebApplication.model.WebApplicationReport;
import com.example.webapplication.WebApplication.service.WebApplicationReportService;
import com.example.webapplication.WebApplication.utils.ResponseModel;
import lombok.AllArgsConstructor;
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
            this.webApplicationReportService.addOrUpdateReport(webApplicationReport.getProjectId(), webApplicationReport);
            return ResponseModel.success("Report added successfully");
        } catch (Exception e) {
            return ResponseModel.error(e.getMessage());
        }
    }

    @PostMapping("/summary-observation")
    public ResponseEntity<Object> addOrUpdateSummaryObservation(@RequestBody WebApplicationReport webApplicationReport) {
        try {
            this.webApplicationReportService.addOrUpdateSummaryObservation(webApplicationReport.getProjectId(), webApplicationReport);
            return ResponseModel.success("Summary of observations added/updated successfully");
        } catch (Exception e) {
            return ResponseModel.error(e.getMessage());
        }
    }

    @PostMapping("/vulnerability/{projectId}")
    public ResponseEntity<Object> addOrUpdateVulnerability(@PathVariable long projectId,
                                                           @RequestParam String name,
                                                           @RequestParam String summary,
                                                           @RequestParam String remedy,
                                                           @RequestParam List<String> remedyReference,
                                                           @RequestParam String resourceAffected,
                                                           @RequestParam String proofOfVulnerability,
                                                           @RequestParam String proofOfVulnerabilityType,
                                                           @RequestParam MultipartFile file) {
        try {
             this.webApplicationReportService.addOrUpdateVulnerability(
                    projectId, name, summary, remedy, remedyReference,resourceAffected, proofOfVulnerability,
                    proofOfVulnerabilityType, file);
            return ResponseModel.success("Vulnerability details added/updated successfully");
        } catch (Exception e) {
            return ResponseModel.error(e.getMessage());
        }
    }

    @GetMapping("/key-finding/{projectId}")
    public ResponseEntity<Object> getKeyFindingsByProjectId(@PathVariable long projectId) {
        try {
            List<KeyFinding> keyFindings = this.webApplicationReportService.getKeyFindingsByProjectId(projectId);
            return ResponseModel.success("Key findings fetched successfully", keyFindings);
        } catch (Exception e) {
            return ResponseModel.error(e.getMessage());
        }
    }

    @GetMapping("/summary-observation/{projectId}")
    public ResponseEntity<Object> getSummaryObservationsByProjectId(@PathVariable long projectId) {
        try {
            List<SummaryOfObservation> summaryObservations = this.webApplicationReportService.getSummaryObservationsByProjectId(projectId);
            return ResponseModel.success("Summary of observations fetched successfully", summaryObservations);
        } catch (Exception e) {
            return ResponseModel.error(e.getMessage());
        }
    }

    @GetMapping("/VulnerabilityDetails/{projectId}")
    public ResponseEntity<?> getVulnerabilityDetails(@PathVariable long projectId) {
        try {
            // Fetch the vulnerability details by projectId
            List<VulnerabilityDetails> vulnerabilityDetailsList = this.webApplicationReportService.getVulnerabilityDetailsByProjectId(projectId);
            return ResponseEntity.ok(vulnerabilityDetailsList);
        } catch (Exception e) {
            return ResponseModel.error(e.getMessage());
        }
    }



}

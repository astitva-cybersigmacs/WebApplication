package com.example.webapplication.WebApplication.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "web_application_report", uniqueConstraints = @UniqueConstraint(columnNames = {"reportId"}))
public class WebApplicationReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "web_application_report_id")
    private long webApplicationReportId;

    private long projectId;
    private long reportId;

    @OneToMany(mappedBy = "webApplicationReport", cascade = CascadeType.ALL)
    private List<KeyFinding> keyFindingList;

    @OneToMany(mappedBy = "webApplicationReport", cascade = CascadeType.ALL)
    private List<SummaryOfObservation> summaryOfObservationList;

    @OneToMany(mappedBy = "webApplicationReport", cascade = CascadeType.ALL)
    private List<VulnerabilityDetails> vulnerabilityDetailsList;



}

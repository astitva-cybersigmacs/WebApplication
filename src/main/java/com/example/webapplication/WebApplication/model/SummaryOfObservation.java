package com.example.webapplication.WebApplication.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "summary_of_observation")
public class SummaryOfObservation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "summary_of_observation_id")
    private long summaryOfObservationId;

    private String vulnerabilityName;
    private String affectingAsset;
    private String status;

    private int cvsScore;

    @Enumerated(EnumType.STRING)
    private Impact impact;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "web_application_report_id")
    @JsonIgnore
    private WebApplicationReport webApplicationReport;


}

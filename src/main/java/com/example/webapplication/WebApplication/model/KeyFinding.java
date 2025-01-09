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
@Table(name = "key_finding")
public class KeyFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "key_finding_id")
    private long keyFindingId;

    private String keyIssue;
    private String controlArea;

    @Enumerated(EnumType.STRING)
    private Impact impact;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "web_application_report_id")
    @JsonIgnore
    private WebApplicationReport webApplicationReport;
}

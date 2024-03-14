package com.g2ops.sbom;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class VulnerabilitiesRecord {
	
	private String cveID;
	private List<Integer> cweID = new ArrayList<>();
	private String[] osvdbID;
	private String cvssVector;
	private Double cvssBaseScore;
	private String cvssTempScore;
	private String cvssTempVector;
	private String recommendation;
	private Date publishedDate;
	private String description;
	private String riskFactor;
	private String exploitAvailable;
	
	// Getters & setters. 
	public String getCveID() {
		return cveID;
	}
	public void setCveID(String cveID) {
		this.cveID = cveID;
	}
	public List<Integer> getCweID() {
		return cweID;
	}
	public void setCweID(List<Integer> cweID) {
		this.cweID = cweID;
	}
	public Double getCvssBaseScore() {
		return cvssBaseScore;
	}
	public void setCvssBaseScore(Double cvssBaseScore) {
		this.cvssBaseScore = cvssBaseScore;
	}
	public String getCvssTemporalScore() {
		return cvssTempScore;
	}
	public void setCvssTemporalScore(String cvssTempScore) {
		this.cvssTempScore = cvssTempScore;
	}
	public String[] getOsvdbID() {
		return osvdbID;
	}
	public void setOsvdbID(String[] osvdbID) {
		this.osvdbID = osvdbID;
	}
	public String getCvssTemporalVector() {
		return cvssTempVector;
	}
	public void setCvssTemporalVector(String cvssTemporalVector) {
		this.cvssTempVector = cvssTemporalVector;
	}
	public String getCvssVector() {
		return cvssVector;
	}
	public void setCvssVector(String cvssVector) {
		this.cvssVector = cvssVector;
	}
	public String getRecommendation() {
		return recommendation;
	}
	public void setRecommendation(String recommendation) {
		this.recommendation = recommendation;
	}
	public  Date getPublishedDate() {
		return publishedDate;
	}
	public void setPublishedDate (Date publishedDate) {
		this.publishedDate = publishedDate;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public String getRiskFactor() {
		return riskFactor;
	}
	public void setRiskFactor(String riskFactor) {
		this.riskFactor = riskFactor;
	}
	public String getExploitAvailable() {
		return exploitAvailable;
	}
	public void setExploitAvailable(String exploitAvailable) {
		this.exploitAvailable = exploitAvailable;
	}

}

package com.g2ops.sbom;

import java.util.Date;

public class VulnerabilitiesRecord {
	
	private String cveID;
	private String cweID;
	private String[] osvdbID;
	private String cvssVector;
	private String cvssBaseScore;
	private String cvssTempScore;
	private String cvssTempVector;
	private String recommendation;
	private String publishedDate;
	private String description;
	
	// Getters & setters. 
	public String getCveID() {
		return cveID;
	}
	public void setCveID(String cveID) {
		this.cveID = cveID;
	}
	public String getCweID() {
		return cweID;
	}
	public void setCweID(String cweID) {
		this.cweID = cweID;
	}
	public String getCvssBaseScore() {
		return cvssBaseScore;
	}
	public void setCvssBaseScore(String string) {
		this.cvssBaseScore = string;
	}
	public String getCvssTemporalScore() {
		return cvssTempScore;
	}
	public void setCvssTemporalScore(String cvssTemporalScore) {
		this.cvssTempScore = cvssTemporalScore;
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
	public String getPublishedDate() {
		return publishedDate;
	}
	public void setPublishedDate(String publishedDate) {
		this.publishedDate = publishedDate;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}

}

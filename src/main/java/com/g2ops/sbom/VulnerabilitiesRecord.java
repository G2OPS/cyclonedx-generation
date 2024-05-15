package com.g2ops.sbom;

import java.util.Date;

public class VulnerabilitiesRecord {
	
	private String cveID;
	private Integer cweID;
	private String cvssVector;
	private Double cvssBaseScore;
	private String cvssTempScore;
	private String cvssTempVector;
	private String recommendation;
	private Date publishedDate;
	private String description;
	private String riskFactor;
	private String exploitAvailable;
	private String port;
	private String pluginName;
	
	
	// Getters & setters. 
	public String getCveID() {
		return cveID;
	}
	public void setCveID(String cveID) {
		this.cveID = cveID;
	}
	public Integer getCweID() {
		return cweID;
	}
	public void setCweID(Integer cweID) {
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
	public String getPort() {
		return port;
	}
	public void setPort(String port) {
		this.port = port;
	}
	public String getPluginName() {
		return pluginName;
	}
	public void setPluginName(String pluginName) {
		this.pluginName = pluginName;
	}

}

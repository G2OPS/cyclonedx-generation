package com.g2ops.sbom;

public class ComponentsRecord {
	
	private String cpeId;
	private String part;
	private String vendor;
	private String product;
	private String version;
	private String description;
	
	// Setters & getters for Cpe Id components. 
	public void setCpeId(String cpeId) {
		this.cpeId = cpeId;
	}
	
	public String getCpeId() {
		return cpeId;
	}
	public void setPart(String part) {
		this.part = part;
	}
	
	public String getPart() {
		return part;
	}
	
	public void setVendor(String vendor) {
		this.vendor = vendor;
	}
	
	public String getVendor() {
		return vendor;
	}

	public String getProduct() {
		return product;
	}

	public void setProduct(String product) {
		this.product = product;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}
	
	public String getDescription() {
		return description;
	}
	
	public void setDescription(String description) {
		this.description = description;
	}
}

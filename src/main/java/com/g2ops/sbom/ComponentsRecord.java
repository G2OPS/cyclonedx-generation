package com.g2ops.sbom;

public class ComponentsRecord {
	
	private String componentCpe;
	private String systemType;
	private String macAddress;
	private String operatingSystem;
	private String reportHostName;
	private String reportHostFqdn;
	
	// Setters & Getters. 
	public String getSytemType() {
		return systemType;
	}

	public void setSystemType(String systemTypeName) {
		this.systemType = systemTypeName;
	}

	public String getMacAddress() {
		return macAddress;
	}

	public void setMacAddress(String macAddressName) {
		this.macAddress = macAddressName;
	}

	public String getOperatingSystem() {
		return operatingSystem;
	}

	public void setOperatingSystem(String operatingSystemName) {
		this.operatingSystem = operatingSystemName;
	}

	public String getReportHostName() {
		return reportHostName;
	}

	public void setReportHostName(String hostName) {
		this.reportHostName = hostName;
	}

	public String getComponentCpe() {
		return componentCpe;
	}

	public void setComponentCpe(String cpe) {
		this.componentCpe = cpe;
	}

}

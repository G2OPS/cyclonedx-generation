package com.g2ops.sbom;

public class ComponentsRecord {
	
	private String componentName;
	private String componentCpe;
	private String operatingSystem;
	private String vendorName;
	private String componentType;
	private String componentVersion;

	
	// Setters & Getters. 
	public String getComponentVersion() {
		return componentVersion;
	}
	
	public void setComponentVersion(String componentVersion) {
		this.componentVersion = componentVersion;
	}
	
	public String getComponentType() {
		return componentType;
	}
	
	public void setComponentType(String componentType) {
		this.componentType = componentType;
	}
	
	public String getComponentName() {
		return componentName;
	}
	
	public void setComponentName(String componentName) {
		 this.componentName = componentName;
	}
	public String getOperatingSystem() {
		return operatingSystem;
	}

	public void setOperatingSystem(String operatingSystemName) {
		this.operatingSystem = operatingSystemName;
	}

	public String getComponentCpe() {
		return componentCpe;
	}

	public void setComponentCpe(String cpe) {
		this.componentCpe = cpe;
	}
	
	public String getVendorName() {
		return vendorName;
	}
	
	public void setVendorName(String vendorName) {
		this.vendorName = vendorName;
	}
}

package com.g2ops.sbom;

public class ComponentsRecord {
	
	private String componentName;
	private String componentCpe;
	private String operatingSystem;

	
	// Setters & Getters. 
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

}

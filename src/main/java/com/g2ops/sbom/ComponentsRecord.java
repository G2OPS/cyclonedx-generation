package com.g2ops.sbom;

public class ComponentsRecord {
	
	// Software Components.
	private String swCpeId;
	private String swPart;
	private String swVendor;
	private String swProduct;
	private String swVersion;
	private String swExternalRefs;
	
	// Hardware Components. 
	private String hwName;
	private String hwVendor;
	private String hwDescription;
	private String hwType;
	private String hwMacAddres;
	private String hwOS;
	
	// Setters & Getters. 
	public void setSwCpeId(String cpeId) {
		this.swCpeId = cpeId;
	}
	
	public String getSwCpeId() {
		return swCpeId;
	}
	public void setSwPart(String part) {
		this.swPart = part;
	}
	
	public String getSwPart() {
		return swPart;
	}
	
	public void setSwVendor(String vendor) {
		this.swVendor = vendor;
	}
	
	public String getSwVendor() {
		return swVendor;
	}

	public String getSwProduct() {
		return swProduct;
	}

	public void setSwProduct(String product) {
		this.swProduct = product;
	}

	public String getSwVersion() {
		return swVersion;
	}

	public void setSwVersion(String version) {
		this.swVersion = version;
	}

	public String getSwExternalRefs() {
		return swExternalRefs;
	}

	public void setSwExternalRefs(String externalRefs) {
		this.swExternalRefs = externalRefs;
	}

	public String getHwName() {
		return hwName;
	}

	public void setHwName(String hwName) {
		this.hwName = hwName;
	}

	public String getHwVendor() {
		return hwVendor;
	}

	public void setHwVendor(String hwVendor) {
		this.hwVendor = hwVendor;
	}

	public String getHwDescription() {
		return hwDescription;
	}

	public void setHwDescription(String hwDescription) {
		this.hwDescription = hwDescription;
	}

	public String getHwType() {
		return hwType;
	}

	public void setHwType(String hwType) {
		this.hwType = hwType;
	}

	public String getHwMacAddres() {
		return hwMacAddres;
	}

	public void setHwMacAddres(String hwMacAddres) {
		this.hwMacAddres = hwMacAddres;
	}

	public String getHwOS() {
		return hwOS;
	}

	public void setHwOS(String hwOS) {
		this.hwOS = hwOS;
	}
}

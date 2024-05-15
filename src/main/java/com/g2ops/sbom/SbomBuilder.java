package com.g2ops.sbom;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Date;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Logger;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.cyclonedx.BomGeneratorFactory;
import org.cyclonedx.CycloneDxSchema;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Component.Type;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.LifecycleChoice;
import org.cyclonedx.model.Lifecycles;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.OrganizationalContact;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.vulnerability.Vulnerability;
import org.cyclonedx.model.vulnerability.Vulnerability.Affect;
import org.cyclonedx.model.vulnerability.Vulnerability.Rating;
import org.cyclonedx.model.vulnerability.Vulnerability.Rating.Method;
import org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity;
import org.cyclonedx.model.vulnerability.Vulnerability.Source;

public class SbomBuilder {

	private static final Logger LOGGER = Logger.getLogger(SbomBuilder.class.getName());

	private static String outputPath = System.getProperty("user.home") + "/OneDrive - G2 Ops, Inc/Desktop/";
	private static List<Hash> hashes = new ArrayList<>();
	private static Map<String, Set<String>> cveReportHostMap = NessusParser.getCveReportHostMap();

	public static void generateSBOM() {

		List<ComponentsRecord> componentRecords = NessusParser.getComponentsList();
		List<VulnerabilitiesRecord> vulnRecords = NessusParser.getVulnerabiltiesRecord();
		List<Dependency> dependencyRecords = NessusParser.getDependenciesList();

		Bom bom = new Bom();

		bom.setMetadata(createMetadata());
		bom.setSerialNumber("urn:uuid:" + UUID.randomUUID());

		// Iterate through all components in the list & add them to BOM.
		for (ComponentsRecord componentRecord : componentRecords) {

			Component component = new Component();
			
			String componentName = componentRecord.getReportHostName();	
			component.setBomRef(String.format("%s.%s",componentName,RandomStringUtils.randomNumeric(8)));
			component.setName(componentRecord.getReportHostName());
			component.setType(Component.Type.APPLICATION);
			component.setCpe(componentRecord.getComponentCpe());
			component.setHashes(hashes);

			// Set Component Properties.
			List<Property> componentPropertiesList = new ArrayList<>();

			if (componentRecord.getSytemType() != null) {
				Property hwProperty = new Property();
				hwProperty.setName("cdx:device:systemType");
				hwProperty.setValue(componentRecord.getSytemType());
				componentPropertiesList.add(hwProperty);
			}
			if (componentRecord.getOperatingSystem() != null) {
				Property hwProperty = new Property();
				hwProperty.setName("cdx:device:operatingSystem");
				hwProperty.setValue(componentRecord.getOperatingSystem());
				componentPropertiesList.add(hwProperty);
			}
			if (componentRecord.getMacAddress() != null) {
				Property hwProperty = new Property();
				hwProperty.setName("cdx:device:macAddress");
				hwProperty.setValue(componentRecord.getMacAddress());
				componentPropertiesList.add(hwProperty);
			}
			
			component.setProperties(componentPropertiesList);
			
			bom.addComponent(component);
		}

		// Iterate through all vulnerabilities in the list & add them to BOM.
		List<Vulnerability> vulnerabilityList = new ArrayList<>();

		for (VulnerabilitiesRecord vulnRecord : vulnRecords) {

			// Set all vulnerability data.
			Vulnerability vulnerability = new Vulnerability();

			String cveID = vulnRecord.getCveID();
			vulnerability.setId(cveID);
			vulnerability.setBomRef(String.format("%s-%S", cveID, RandomStringUtils.randomAlphanumeric(8)));
			vulnerability.setSource(setSourceType(cveID));
			vulnerability.setAffects(setAffectedHost(cveID));
			vulnerability.setCwes(convertToList(vulnRecord.getCweID()));
			vulnerability.setPublished(vulnRecord.getPublishedDate());
			vulnerability.setRecommendation(vulnRecord.getRecommendation());
			vulnerability.setDescription(vulnRecord.getDescription());

			// Set ratings for each vulnerability found.
			Rating rating = new Rating();

			List<Vulnerability.Rating> ratingsList = new ArrayList<>();
			rating.setScore(vulnRecord.getCvssBaseScore());
			rating.setVector(vulnRecord.getCvssVector());
			rating.setMethod(setMethodType(vulnRecord.getCvssVector()));
			rating.setSeverity(setSeverityType(vulnRecord.getRiskFactor()));

			ratingsList.add(rating);
			vulnerability.setRatings(ratingsList);

			// Set add'l properties for each vulnerability found.
			List<Property> propertyList = new ArrayList<>();

			if (vulnRecord.getCvssTemporalScore() != null) {
				Property scoreProperty = new Property();
				scoreProperty.setName("cdx:vulnerability:cvssTemporalscore");
				scoreProperty.setValue(vulnRecord.getCvssTemporalScore());
				propertyList.add(scoreProperty);
			}

			if (vulnRecord.getCvssTemporalVector() != null) {
				Property vectorProperty = new Property();
				vectorProperty.setName("cdx:vulnerability:cvssTemporalvector");
				vectorProperty.setValue(vulnRecord.getCvssTemporalVector());
				vectorProperty.setValue("Dummy");
				propertyList.add(vectorProperty);
			}

			if (vulnRecord.getExploitAvailable() != null) {
				Property exploitProperty = new Property();
				exploitProperty.setName("cdx:vulnerability:exploitAvailable");
				exploitProperty.setValue(vulnRecord.getExploitAvailable());
				propertyList.add(exploitProperty);
			}

			if (vulnRecord.getPort() != null) {
				Property portProperty = new Property();
				portProperty.setName("cdx:vulnerability:portNumber");
				portProperty.setValue(vulnRecord.getPort());
				propertyList.add(portProperty);
			}
			
			if (vulnRecord.getPluginName() != null) {
				Property vulnPluginName = new Property();
				vulnPluginName.setName("cdx:vulnerability:pluginName");
				vulnPluginName.setValue(vulnRecord.getPluginName());
				propertyList.add(vulnPluginName);
			}
			
			vulnerability.setProperties((List<Property>) propertyList);

			vulnerabilityList.add(vulnerability);
			bom.setVulnerabilities(vulnerabilityList);

		}

		// Set Dependencies for the SBOM. 
		bom.setDependencies(dependencyRecords);
		
		// Generate hashes.
		generateHash("md5");
		generateHash("sha1");
		generateHash("sha256");

		// Write SBOM in JSON & XML versions.
		writeSBOM(bom);
	}

	/**
	 * Writes SBOM in Json & Xml formats to the specified output path.
	 * 
	 * @param bom  - bom object.
	 * @param path - set output path.
	 */
	private static void writeSBOM(Bom bom) {
		try {
			FileWriter jsonWriter = new FileWriter(outputPath + "sbom.json", false);
			jsonWriter.write(BomGeneratorFactory.createJson(CycloneDxSchema.VERSION_LATEST, bom).toJsonString());
			jsonWriter.close();

			FileWriter xmlWriter = new FileWriter(outputPath + "sbom.xml", false);
			xmlWriter.write(String.valueOf(BomGeneratorFactory.createXml(CycloneDxSchema.VERSION_LATEST, bom)));
			xmlWriter.close();

			LOGGER.info("SBOM generation complete.");

		} catch (Exception e) {
			LOGGER.info("Error generating SBOM:" + e.getMessage());
		}
	}

	/**
	 * Sets metadata such as build process, organization info and such for the BOM. 
	 * 
	 * @return metadata - An instance of Metadata.
	 */
	private static Metadata createMetadata() {
		
		Metadata metadata = new Metadata();

		Date currTimestamp = new Date(System.currentTimeMillis());
		metadata.setTimestamp(currTimestamp);
		
		OrganizationalContact author = new OrganizationalContact();
		
		author.setName("G2 Ops Inc");
		author.setEmail("info@g2-ops.com");
		metadata.addAuthor(author);
		
		List<LifecycleChoice> lifeCycles = new ArrayList<>();
		Lifecycles phase = new Lifecycles();
		LifecycleChoice phaseChoice = new LifecycleChoice();
		
		phaseChoice.setPhase(LifecycleChoice.Phase.POST_BUILD);
		lifeCycles.add(phaseChoice);
		phase.setLifecycleChoice(lifeCycles);
		metadata.setLifecycles(phase);
		
		Component metadataComponent = new Component();
		metadataComponent.setType(Type.FILE);
		metadataComponent.setName(SbomGui.getSelectedFileName());
		metadata.setComponent(metadataComponent);
		
		//TODO
		Property scanTypeProperty = new Property();
		Property scanVersionProperty = new Property();
		
		List<Property> propertyList = new ArrayList<>();
		scanTypeProperty.setName("nessus:scan:type");
		scanTypeProperty.setValue("normal");
		scanVersionProperty.setName("nessus:scan:version");
		scanVersionProperty.setValue("6.9.0");
		
		propertyList.add(scanTypeProperty);
		propertyList.add(scanVersionProperty);
		
		metadata.setProperties(propertyList);
		
		return metadata;
	}

	/**
	 * Generates hash for json & xml sboms and writes each algorithm to its own
	 * file.
	 * 
	 * @param bom        - bom object.
	 * @param path       - output path.
	 * @param algorithm  - hashing algorithm to be used.
	 * @param fileFormat - expected file format.
	 */
	private static void generateHash(String algorithm) {
		try {
			Path sbomPath = Paths.get(outputPath + "sbom.json");
			byte[] sbomBytes = Files.readAllBytes(sbomPath);

			Hash hash = null;

			if (algorithm.equals("md5")) {
				hash = new Hash(Hash.Algorithm.MD5, DigestUtils.md5Hex(sbomBytes));
			}
			if (algorithm.equals("sha1")) {
				hash = new Hash(Hash.Algorithm.SHA1, DigestUtils.sha1Hex(sbomBytes));
			}
			if (algorithm.equals("sha256")) {
				hash = new Hash(Hash.Algorithm.SHA_256, DigestUtils.sha256Hex(sbomBytes));
			}

			if (hash != null) {
				hashes.add(hash);
			}

			FileWriter hashWriter = new FileWriter(outputPath + algorithm + ".json", false);
			hashWriter.write(hash.getValue());
			hashWriter.close();

		} catch (IOException e) {
			LOGGER.info("Error generating hashes: " + e.getMessage());
		}

	}

	/**
	 * Sets the Severity Type based on the risk factor for each vulverability.
	 * 
	 * @param Risk factor.
	 * @return Severity
	 */
	private static Severity setSeverityType(String riskFactor) {
		Severity severityType = null;
		if (riskFactor.equalsIgnoreCase("critical")) {
			severityType = Severity.CRITICAL;
		}
		if (riskFactor.equalsIgnoreCase("high")) {
			severityType = Severity.HIGH;
		}
		if (riskFactor.equalsIgnoreCase("low")) {
			severityType = Severity.LOW;
		}
		if (riskFactor.equalsIgnoreCase("info")) {
			severityType = Severity.INFO;
		}
		if (riskFactor.equalsIgnoreCase("none")) {
			severityType = Severity.NONE;
		}
		if (riskFactor.equalsIgnoreCase("unknown")) {
			severityType = Severity.UNKNOWN;
		}
		return severityType;
	}

	/**
	 * Sets source URL and Name for each CVE.
	 * 
	 * @param cveID
	 */
	private static Source setSourceType(String cveID) {
		Source source = new Source();
		source.setName("National Vulnerability Database");
		source.setUrl(String.format("https://nvd.nist.gov/vuln/detail/%s", cveID));
		return source;
	}

	/**
	 * Sets Method used to determine the CVSS Vector.
	 * 
	 * @param cvssVector - vector from the vuln record.
	 * @return method - Method object with the rating.
	 */
	private static Method setMethodType(String cvssVector) {
		Method method = Vulnerability.Rating.Method.CVSSV2; // Default to CVSS2.

		// Extract method from cvss vector.
		if (cvssVector != null) {
			int index = cvssVector.indexOf("#");
			String methodVector = index != -1 ? cvssVector.substring(0, index) : cvssVector;

			if (methodVector.equalsIgnoreCase("CVSS3")) {
				method = Vulnerability.Rating.Method.CVSSV3;
			}
		}

		return method;
	}

	/**
	 * Sets the afffected hosts for each vulnerability found.
	 * 
	 * @param cveID - cve id found in the report item.
	 * @return affectedHosts list - List that contains the references to all hosts.
	 */
	private static List<Affect> setAffectedHost(String cveID) {
		List<Affect> affectedHosts = new ArrayList<>();
		// match the key based on cve id passed in.
		if (cveReportHostMap.containsKey(cveID)) {
			Set<String> hosts = cveReportHostMap.get(cveID);
			// loop through the hosts and set to refs.
			for (String host : hosts) {
				Affect affect = new Affect();
				affect.setRef(host);
				affectedHosts.add(affect);
			}
		}
		return affectedHosts;
	}
	
	
	/**
	 * 
	 * @param cweID
	 * @return
	 */
	private static List<Integer> convertToList(Integer cweID) {
		List<Integer> cweList = new ArrayList<>();
		cweList.add(cweID);
		return cweList;

	}
	
}

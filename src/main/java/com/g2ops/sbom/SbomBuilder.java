package com.g2ops.sbom;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Date;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.cyclonedx.BomGeneratorFactory;
import org.cyclonedx.CycloneDxSchema;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Component.Type;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.OrganizationalContact;
import org.cyclonedx.model.OrganizationalEntity;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.metadata.ToolInformation;
import org.cyclonedx.model.vulnerability.Vulnerability;
import org.cyclonedx.model.vulnerability.Vulnerability.Rating;
import org.cyclonedx.model.vulnerability.Vulnerability.Rating.Method;
import org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity;
import org.cyclonedx.model.vulnerability.Vulnerability.Source;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;


public class SbomBuilder {

	private static String desktopPath = System.getProperty("user.home") + "/OneDrive - G2 Ops, Inc/Desktop/";
	private static final Logger LOGGER = Logger.getLogger(SbomBuilder.class.getName());

	public static void generateSbom() {

		List<ComponentsRecord> swComponentsRecord = NessusParser.getComponentsRecord();
		List<VulnerabilitiesRecord> vulnRecords = NessusParser.getVulnerabiltiesRecord();

		Bom bom = new Bom();
		bom.setMetadata(createMetadata());
		bom.setSerialNumber("urn:uuid:"+ UUID.randomUUID());
		
		if (swComponentsRecord != null) {

			Component swComponent = new Component();
			
			for (ComponentsRecord componentRecord : swComponentsRecord) {
				
				swComponent.setHashes(generateHashes());
				swComponent.setCpe(componentRecord.getSwCpeId());
				swComponent.setName(componentRecord.getSwProduct());
				swComponent.setVersion(componentRecord.getSwVersion());
				swComponent.setType(setComponentType(componentRecord.getSwPart()));
				swComponent.setSupplier(setOrganizationalEntity(componentRecord.getSwVendor()));
				swComponent.setExternalReferences(createExternalRefs(componentRecord.getSwExternalRefs()));
				swComponent.setBomRef(componentRecord.getSwProduct() + "-" + swComponent.getHashes().get(0).getValue());
				bom.addComponent(swComponent);
			}
			
			// New Component to list out packages / libs used to build the SBOM. 
			Component toolsUsedComponent = new Component();
			toolsUsedComponent.setComponents(toolsUsed());
			// Add all Components to BOM. 
			bom.addComponent(toolsUsedComponent);

		} else {
			LOGGER.info("The selected Nessus file(s) did not have CPE plugins enabled.");
		}
		
		List<Vulnerability> vulnerabilityList = new ArrayList<>();
		
		if (vulnRecords != null) {
			for (VulnerabilitiesRecord vulnRecord : vulnRecords) {
				
				// Set all vulnerability data. 
				Vulnerability  vulnerability = new Vulnerability();
				
				vulnerability.setId(vulnRecord.getCveID());
				vulnerability.setCwes(vulnRecord.getCweID());
				vulnerability.setPublished(vulnRecord.getPublishedDate());
				vulnerability.setSource(setSourceType(vulnRecord.getCveID()));
				vulnerability.setRecommendation(vulnRecord.getRecommendation());
				vulnerability.setDescription(getDescription(vulnerability.getSource().getUrl()));
				vulnerability.setBomRef(String.format("%s-%s", vulnRecord.getCveID(),randomHashLen()));
				
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
					scoreProperty.setName("cvss temporal score");
					scoreProperty.setValue(vulnRecord.getCvssTemporalScore());
					propertyList.add(scoreProperty);
				}
				
				if (vulnRecord.getCvssTemporalVector() != null) {
					Property vectorProperty = new Property();
					vectorProperty.setName("cvss temporal vector");
					vectorProperty.setValue(vulnRecord.getCvssTemporalVector());
					propertyList.add(vectorProperty);
				}
				
				if (vulnRecord.getExploitAvailable() != null) {
				    Property exploitProperty = new Property();
				    exploitProperty.setName("exploit available");
				    exploitProperty.setValue(vulnRecord.getExploitAvailable());
				    propertyList.add(exploitProperty);
				}
				
				vulnerability.setProperties((List<Property>) propertyList);
				
				vulnerabilityList.add(vulnerability);
				bom.setVulnerabilities(vulnerabilityList); 	
				
			}
		} else {
			LOGGER.info("The selected Nessus file(s) did not contain vulnerability data");
		}

		// Write both JSON and XML versions.
		try {
			
			FileWriter jsonWriter = new FileWriter(desktopPath + "sbom.json", false);
			jsonWriter.write(BomGeneratorFactory.createJson(CycloneDxSchema.VERSION_LATEST, bom).toJsonString());
			jsonWriter.close();

			FileWriter xmlWriter = new FileWriter(desktopPath + "sbom.xml", false);
			xmlWriter.write(String.valueOf(BomGeneratorFactory.createXml(CycloneDxSchema.VERSION_LATEST, bom)));
			xmlWriter.close();

			LOGGER.info("Sbom generation complete.");

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * Creates and sets metadata for the SBOM.
	 * 
	 * @return An instance of Metadata.
	 */
	private static Metadata createMetadata() {
		Metadata metadata = new Metadata();
		OrganizationalContact author = new OrganizationalContact();

		Date currTimestamp = new Date(System.currentTimeMillis());
		metadata.setTimestamp(currTimestamp);
		author.setName("G2 Ops Inc");
		author.setEmail("info@g2-ops.com");
		author.setPhone("757-965-8330");
		metadata.addAuthor(author);

//		ToolInformation toolInformation = new ToolInformation();
//		toolInformation.setComponents(toolsUsed());
//		metadata.setToolChoice(toolInformation);
		
		metadata.setComponent(getProjectComponent());
		
		return metadata;
	}
	
	/**
	 * Genrates hash algorithms of random lengths. 
	 * 
	 * @return Hash List. 
	 */	
	private static List<Hash> generateHashes(){
		
		Hash md5 = new Hash(Hash.Algorithm.MD5, randomHashLen());
		Hash sha256 = new Hash(Hash.Algorithm.SHA_256, randomHashLen());
		Hash sha512 = new Hash(Hash.Algorithm.SHA_512, randomHashLen());
		
		List<Hash> hashList = Arrays.asList(md5,sha256,sha512);
		
		return hashList;
	}
	                            
	/**
	 * Creates a string of random desired lengths.
	 * 
	 * @return A random alphanumeric string.
	 */
	private static String randomHashLen() {
		int[] desiredLength = { 32, 40, 64, 96, 128 };
		int randomLengthIndex = (int) (Math.random() * desiredLength.length);
		int randomLength = desiredLength[randomLengthIndex];

		return RandomStringUtils.randomAlphanumeric(randomLength);
	}
	 
	/**
	 * Sets the Component Type for each SW component in the SBOM based
	 * on the cpe id part. 
	 * 
	 * @param Cpe ID Part component.
	 */
	private static Type setComponentType(String part) {
		Type componentType = null;
		if (part.equalsIgnoreCase("a")) {
			componentType = Component.Type.APPLICATION;
		}
		if (part.equalsIgnoreCase("o")) {
			componentType = Component.Type.OPERATING_SYSTEM;
		}
		if (part.equalsIgnoreCase("h")) {
			componentType = Component.Type.DEVICE;
		}
		return componentType;
	}
	 
    /**
     * Sets the Organizational Entity for each SW component in the SBOM based
     * on the cpe id vendor. 
     * 
     * @param Cpe ID Vendor component.
     */
	private static OrganizationalEntity setOrganizationalEntity(String vendor) {
		OrganizationalEntity organizationalEntity = new OrganizationalEntity();
		organizationalEntity.setName(vendor);
		return organizationalEntity;
	}
	
	/**
	 * Sets the Severity Type based on the risk factor for each vulverability. 
	 * 
	 * @param Risk factor.
	 * @return Severity
	 */
	private static Severity setSeverityType(String riskFactor) {
		Severity severityType = null;
		if(riskFactor.equalsIgnoreCase("critical")) {
			severityType = Severity.CRITICAL;
		}
		if(riskFactor.equalsIgnoreCase("high")) {
			severityType = Severity.HIGH;
		}
		if(riskFactor.equalsIgnoreCase("low")) {
			severityType = Severity.LOW;
		}
		if(riskFactor.equalsIgnoreCase("info")) {
			severityType = Severity.INFO;
		}
		if(riskFactor.equalsIgnoreCase("none")) {
			severityType = Severity.NONE;
		}
		if(riskFactor.equalsIgnoreCase("unknown")) {
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
	
	private static Method setMethodType(String cvssVector) {
		Method method = null;
		
		// Extract method from cvss vector.
		if (cvssVector != null) {
			String methodVector = cvssVector.substring(0, cvssVector.indexOf("#"));
			
			if (methodVector.equalsIgnoreCase("CVSS2")) {
				method = Vulnerability.Rating.Method.CVSSV2;
			}
			if (methodVector.equalsIgnoreCase("CVSS3")) {
				method = Vulnerability.Rating.Method.CVSSV3;
			}
		}

		return method;
	}
	
	/**
	 * Connect to the CVE url and extracts description p<>
	 * 
	 * @param CVE-ID url.
	 * 
	 */
	private static String getDescription(String url) {
		String descriptionText = null;
		try {
			Document doc = Jsoup.connect(url).get();
			Element descriptionElement = doc.select("p[data-testid=vuln-description]").first();

			if (descriptionElement != null) {
				descriptionText = descriptionElement.text();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return descriptionText;
	}
	
	/**
	 * Uses PackageURL Builder to create a purl from a given CPE ID. 
	 * 
	 * @param cpeID
	 */
	private static PackageURL createPurl(String cpeID) {
		PackageURL purl = null;
		try {
			// Spilt CPE ID into parts and set [] values.
			String[] parts = cpeID.split(":");
			String cpePart = parts[2];
			String cpeVendor = parts[3];
			String cpeProduct = parts[4];

			// Set valuves for Package Builder.
			PackageURLBuilder purlBuilder = PackageURLBuilder.aPackageURL().withType(cpePart).withNamespace(cpeVendor).withName(cpeProduct);

			// Check if the version exists in the cpeID.
			if (parts.length > 5) {
				String cpeVersion = parts[5];
				purlBuilder.withVersion(cpeVersion);
			} 
				
			// Build PURL.
			purl = purlBuilder.build();
			

		} catch (MalformedPackageURLException e) {
			e.printStackTrace();
		}

		return purl;
	}
	
	/**
	 * Takes in references from componet record and sets type & url.
	 * 
	 * @param References
	 */
	private static List<ExternalReference> createExternalRefs(String references) {
		List<ExternalReference> externalRefList = new ArrayList<>();

		// Split the references string by newline characters
		String[] urls = references.split("\\r?\\n");

		for (String url : urls) {
			ExternalReference externalRef = new ExternalReference();
			externalRef.setType(ExternalReference.Type.WEBSITE);
			externalRef.setUrl(url.trim());

			externalRefList.add(externalRef);
		}
		return externalRefList;
	}
	
	/**
	 * Uses maven object model to extract dependencies from the POM. 
	 * 
	 * @return Component List with dependencies. 
	 */
	
	private static List<Component> toolsUsed() {
		List<Component> componentsList = new ArrayList<>();
		try {

			MavenXpp3Reader reader = new MavenXpp3Reader();
			Model model = reader.read(new FileReader("pom.xml"));

			// Extract dependencies from POM.
			List<Dependency> dependencies = model.getDependencies();

			for (Dependency dependency : dependencies) {
				
				Component component = new Component();		
				component.setType(Component.Type.LIBRARY);
				component.setName(dependency.getArtifactId());
				component.setGroup(dependency.getGroupId());
				component.setVersion(dependency.getVersion());
				component.setScope(Component.Scope.REQUIRED);
				
				componentsList.add(component);
				
			}

		} catch (IOException | XmlPullParserException e) {
			e.printStackTrace();
		}
		return componentsList;
	}
	
	/**
	 * Extracts project-level information from the pom.xml and set them to Component.
	 * 
	 * @return Project Component.
	 */
	
	private static Component getProjectComponent() {
		List<ExternalReference> projectRefsList = new ArrayList<>();
		Component projectComponent = new Component();
		try {
			MavenXpp3Reader reader = new MavenXpp3Reader();
			Model model = reader.read(new FileReader("pom.xml"));

			String groupId = model.getGroupId();
			String name = model.getArtifactId();
			String version = model.getVersion();
			String url = model.getUrl();

			ExternalReference projectRefs = new ExternalReference();
			projectRefs.setType(ExternalReference.Type.WEBSITE);
			projectRefs.setUrl(url);
			projectRefsList.add(projectRefs);

			projectComponent.setGroup(groupId);
			projectComponent.setName(name);
			projectComponent.setVersion(version);
			projectComponent.setExternalReferences(projectRefsList);

		} catch (IOException | XmlPullParserException e) {
			e.printStackTrace();
		}
		return projectComponent;
	}
	

}

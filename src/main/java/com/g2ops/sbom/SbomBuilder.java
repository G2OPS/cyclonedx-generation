package com.g2ops.sbom;

import java.io.FileWriter;
import java.sql.Date;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;

import org.apache.commons.lang3.RandomStringUtils;
import org.cyclonedx.BomGeneratorFactory;
import org.cyclonedx.CycloneDxSchema;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Component.Type;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.OrganizationalContact;
import org.cyclonedx.model.OrganizationalEntity;

public class SbomBuilder {

	private static String desktopPath = System.getProperty("user.home") + "/OneDrive - G2 Ops, Inc/Desktop/";
	private static final Logger LOGGER = Logger.getLogger(SbomBuilder.class.getName());

	public static void generateSbom() {

		Bom bom = new Bom();
		List<ComponentsRecord> componentsRecords = NessusParser.getComponentsRecord();

		if (componentsRecords != null) {

			for (ComponentsRecord componentRecord : componentsRecords) {

				Component swComponent = new Component();
				swComponent.setCpe(componentRecord.getCpeId());
				swComponent.setName(componentRecord.getProduct());
				swComponent.setVersion(componentRecord.getVersion());
				swComponent.setType(setComponentType(componentRecord.getPart()));
				swComponent.setSupplier(setOrganizationalEntity(componentRecord.getVendor()));
				swComponent.addHash(new Hash(Hash.Algorithm.SHA_256, generateRandomString()));
				swComponent.setBomRef(componentRecord.getProduct() + "-" + swComponent.getHashes().get(0).getValue());

				bom.addComponent(swComponent);
				
				bom.setMetadata(createMetadata());
				bom.setSerialNumber("urn:uuid:"+ UUID.randomUUID());
			}

		} else {
			LOGGER.info("CPE_RECORD is null. Unable to generate SBOM.");
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

		return metadata;
	}
	
	
	/**
	 * Creates a string of random desired lengths.
	 * 
	 * @return A random alphanumeric string.
	 */
	private static String generateRandomString() {
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
			
}

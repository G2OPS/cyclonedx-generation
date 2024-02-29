package com.g2ops.sbom;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import javax.swing.JOptionPane;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class NessusParser {

	private static final Logger LOGGER = Logger.getLogger(NessusParser.class.getName());

	private static final String CPE_PLUGIN_TAG = "Common Platform Enumeration (CPE)";
	private static final String PLUGIN_OUTPUT_TAG = "plugin_output";
	private static final String CVSS_SCORE_TAG = "cvss_base_score";
	private static final List<String> CPE_IDs = new ArrayList<>();
	private static final List<ComponentsRecord> COMPONENTS_RECORD = new ArrayList<>();
	private static final List<VulnerabilitiesRecord> VULNERABILITIES_RECORD = new ArrayList<>();
	

	/**
	 * Reads nessus files and iterates through relevent data fields.
	 * 
	 * @param file input stream.
	 */
	public static void parseXML(InputStream inputStream, File nessusFile) {
		try {
			DocumentBuilderFactory dbfactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dbuilder = dbfactory.newDocumentBuilder();
			Document document = dbuilder.parse(inputStream);

			// Remove any whitespace and structural irregularities.
			document.getDocumentElement().normalize();

			// Get all reportItems.
			NodeList reportItemList = document.getElementsByTagName("ReportItem");
	
			boolean foundCpePlugin = false;
			boolean foundVulnNode = false;

			for (int i = 0; i < reportItemList.getLength(); i++) {
				Node reportItemNode = reportItemList.item(i);

				if (reportItemNode.getNodeType() == Node.ELEMENT_NODE) {
					Element reportItemElement = (Element) reportItemNode;

					// Check if plugin name equals Common Platform Enumeration.
					String pluginName = reportItemElement.getAttribute("pluginName");
					if (CPE_PLUGIN_TAG.equalsIgnoreCase(pluginName)) {
						foundCpePlugin = true;
						// Extract plugin_output tag.
						Node pluginOutputNode = reportItemElement.getElementsByTagName(PLUGIN_OUTPUT_TAG).item(0);

						if (pluginOutputNode != null && pluginOutputNode.getNodeType() == Node.ELEMENT_NODE) {
							Element pluginOutputElement = (Element) pluginOutputNode;

							String pluginOutputContent = pluginOutputElement.getTextContent();
							extractCpeID(pluginOutputContent);
						}
					}
					// Check if reportItem element contains vulnerability data. 
					if (reportItemElement.getElementsByTagName(CVSS_SCORE_TAG) != null) {
						foundVulnNode = true;
						extractVulnData(reportItemElement);
					}
				}

			}
			// Iterate over data list and create records.
			for (String cpeId : CPE_IDs) {
				createComponentRecord(cpeId);
			}
			// Build SBOMs.
			SbomBuilder.generateSbom();

			if (!foundCpePlugin) {
				JOptionPane.showMessageDialog(null, "The selected Nessus file(s) did not have CPE plugins enabled.", "Info", JOptionPane.INFORMATION_MESSAGE);
			}
			
			if (!foundVulnNode) {
				JOptionPane.showMessageDialog(null, "The selected Nessus file(s) did not contain vulnerability data", "Info", JOptionPane.INFORMATION_MESSAGE);
			}

		} catch (ParserConfigurationException | SAXException | IOException e) {
			e.printStackTrace();
		}

	}

	/**
	 * Extracts CPE ID from plugin output tag.
	 * 
	 * @param pluginOutputElemet
	 * @return CPE list.
	 */
	private static List<String> extractCpeID(String pluginOutputContent) {

		int startIndex = pluginOutputContent.indexOf("cpe:");

		while (startIndex != -1) {
			// Find the endIndex once the cpe substring is found.
			int spaceIndex = pluginOutputContent.indexOf(" ", startIndex);
			int newLineIndex = pluginOutputContent.indexOf("\n", startIndex);

			int endIndex;

			if (spaceIndex != -1 && newLineIndex != -1) {
				// If both spaceIndex & newLineIndex are found, choose the one that comes first.
				endIndex = Math.min(spaceIndex, newLineIndex);
			} else {
				// Use the one that is found.
				endIndex = Math.max(spaceIndex, newLineIndex);
			}

			if (endIndex == -1) {
				// If no whitespace or newline is found, then endIndex will end of content.
				endIndex = pluginOutputContent.length();
			}

			String cpeId = pluginOutputContent.substring(startIndex, endIndex).trim();

			// Check for duplicates before adding.
			if (!CPE_IDs.contains(cpeId)) {
				CPE_IDs.add(cpeId);
			}

			// Find the next occurrence of "cpe:" in the remaining content
			startIndex = pluginOutputContent.indexOf("cpe:", endIndex);
		}

		if (CPE_IDs.isEmpty()) {
			LOGGER.info("No cpe found in <plugin_output>");
		}
		return CPE_IDs;
	}
	
	/**
	 * Extracts vulnerability data from reportItem & saves it to vuln record.
	 * 
	 * @param reportItemElement , cvssScore Node. 
	 */	
	private static void extractVulnData(Element reportItemElement) {

		Node cvssScoreElementNode = reportItemElement.getElementsByTagName("cvss_base_score").item(0);
		Node cveElement = reportItemElement.getElementsByTagName("cve").item(0);
		Node cvssTempScoreElement = reportItemElement.getElementsByTagName("cvss_base_score").item(0);
		Node cvssTempVectorElement = reportItemElement.getElementsByTagName("cvss_temporal_vector").item(0);
		Node cvssVectorElement = reportItemElement.getElementsByTagName("cvss_vector").item(0);
		Node cweElement = reportItemElement.getElementsByTagName("cwe").item(0);
		Node recommedationElement = reportItemElement.getElementsByTagName("solution").item(0);
		Node descriptionElement = reportItemElement.getElementsByTagName("description").item(0);
		Node publishedDateElement = reportItemElement.getElementsByTagName("vuln_publication_date").item(0);

		setVulnRecord(cvssScoreElementNode, cveElement, cvssTempScoreElement, cvssTempVectorElement, cvssVectorElement, cweElement, recommedationElement,
				descriptionElement, publishedDateElement);

	}

	/**
	 * Creates Cpe Record, spilts CPE ID and sets indiviual component fields.
	 * 
	 * @param CPE ID.
	 * @return Cpe Record.
	 */
	private static void createComponentRecord(String cpeId) {
		// Format Cpe Id and spilt by the colon.
		String formatCpe = cpeId.replace("/", "2.3:");
		String[] cpeComponents = formatCpe.split(":");

		ComponentsRecord componentRecord = new ComponentsRecord();
		componentRecord.setCpeId(formatCpe);
		componentRecord.setPart(cpeComponents[2]);
		componentRecord.setVendor(cpeComponents[3]);
		componentRecord.setProduct(cpeComponents[4]);

		// Check if version exists before accessing the index.
		if (cpeComponents.length > 5) {
			componentRecord.setVersion(cpeComponents[5]);
		}

		COMPONENTS_RECORD.add(componentRecord);

	}
	
	/**
	 * Creates Vuln Record, checks if an element exits & then adds it to vuln record list. 
	 * 
	 * @param cvssScoreElementNode
	 * @param cveElement
	 * @param cvssTempScoreElement
	 * @param cvssTempVectorElement
	 * @param cvssVectorElement
	 * @param cweElement
	 * @param recommedationElement
	 * @param descriptionElement
	 * @param publishedDateElement
	 */
	private static void setVulnRecord(Node cvssScoreElementNode, Node cveElement, Node cvssTempScoreElement, Node cvssTempVectorElement, Node cvssVectorElement,
			Node cweElement, Node recommedationElement, Node descriptionElement, Node publishedDateElement) {
		
		VulnerabilitiesRecord vulnerabilityRecord = new VulnerabilitiesRecord();

		if (cvssScoreElementNode != null && cvssScoreElementNode.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setCvssBaseScore(cvssScoreElementNode.getTextContent());
		}
		if (cveElement != null && cveElement.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setCveID(cveElement.getTextContent());
		}
		if (cvssTempScoreElement != null && cvssTempScoreElement.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setCvssTemporalScore(cvssTempScoreElement.getTextContent());
		}
		if (cvssTempVectorElement != null && cvssTempVectorElement.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setCvssTemporalVector(cvssTempVectorElement.getTextContent());
		}
		if (cvssVectorElement != null && cvssVectorElement.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setCvssVector(cvssVectorElement.getTextContent());
		}
		if (cweElement != null && cweElement.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setCweID(cweElement.getTextContent());
		}
		if (recommedationElement != null && recommedationElement.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setRecommendation(recommedationElement.getTextContent());
		}
		if (descriptionElement != null && descriptionElement.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setDescription(descriptionElement.getTextContent());
		}
		if (publishedDateElement != null && publishedDateElement.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setPublishedDate(publishedDateElement.getTextContent());
		}
		
		VULNERABILITIES_RECORD.add(vulnerabilityRecord);
	}
	
	// Getter for record lists. 
	public static List<ComponentsRecord> getComponentsRecord() {
		return COMPONENTS_RECORD;
	}
	
	public static List<VulnerabilitiesRecord> getVulnerabiltiesRecord(){
		return VULNERABILITIES_RECORD;
	}

}

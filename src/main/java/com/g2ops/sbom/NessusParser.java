package com.g2ops.sbom;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
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
	private static final String COMMON_VULNERABILITY_TAG = "cve";

	private static List<String> CPE_IDs = new ArrayList<>();
	private static List<ComponentsRecord> SOFTWARE_COMPONENTS_RECORD = new ArrayList<>();
	private static List<ComponentsRecord> HARDWARE_COMPONENTS_RECORD = new ArrayList<>();
	private static List<VulnerabilitiesRecord> VULNERABILITIES_RECORD = new ArrayList<>();
	private static String externalRefsContent;

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
			
			// Get all ReportHosts.
			NodeList reportHostList = document.getElementsByTagName("ReportHost");
			extractHardwareComponents(reportHostList);
			
			// Get all ReportItems. 
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
						Node externalRefsNode = reportItemElement.getElementsByTagName("see_also").item(0);
						
						if (pluginOutputNode  != null && pluginOutputNode.getNodeType() == Node.ELEMENT_NODE) {
							Element pluginOutputElement = (Element) pluginOutputNode;
							// Extract cpe info from plugin output. 
							String pluginOutputContent = pluginOutputElement.getTextContent();
							extractCpeID(pluginOutputContent);
						}
						//Extract external references from external tag node. 
						if (externalRefsNode != null && externalRefsNode.getNodeType() == Node.ELEMENT_NODE) {
							Element externalRefsElement = (Element) externalRefsNode;
							
							externalRefsContent = externalRefsElement.getTextContent();
						
						}
					}
					// Check if reportItem element contains vulnerability data.
					if (reportItemElement.getElementsByTagName(COMMON_VULNERABILITY_TAG).item(0) != null) {
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
	 * Extracts all hardware components info from Nessus file(s). 
	 * 
	 * @param NodeList reportHostList
	 */

	private static void extractHardwareComponents(NodeList reportHostList) {

		for (int i = 0; i < reportHostList.getLength(); i++) {
			Node reportHostNode = reportHostList.item(i);

			if (reportHostNode.getNodeType() == Node.ELEMENT_NODE) {
				Element reportHostElement = (Element) reportHostNode;

				// Get all Host Properties.
				NodeList hostPropertiesList = reportHostElement.getElementsByTagName("HostProperties");
				if (hostPropertiesList.getLength() > 0) {
					Element hostPropertiesElement = (Element) hostPropertiesList.item(0);
					// Check if the system-type tag exists.
					NodeList systemTypeTags = hostPropertiesElement.getElementsByTagName("tag");
					if (systemTypeTags != null) {

						for (int j = 0; j < systemTypeTags.getLength(); j++) {
							Element tagElement = (Element) systemTypeTags.item(j);
							String tagName = tagElement.getAttribute("name");
							
							if (tagName.equalsIgnoreCase("system-type")) {
								// Instantiate Components Record for HW items. 
								ComponentsRecord hwComponentRec = new ComponentsRecord();
								hwComponentRec.setHwType(tagElement.getTextContent());
								// Set other properties if device type is available.
								if (tagName.equalsIgnoreCase("operating-system")) {
									hwComponentRec.setHwOS(tagElement.getTextContent());
								}
								HARDWARE_COMPONENTS_RECORD.add(hwComponentRec);
							}

						}
					}
				}
			}
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
	 * Creates Cpe Record, spilts CPE ID and sets indiviual component fields.
	 * 
	 * @param CPE ID.
	 * @return Cpe Record.
	 */
	private static void createComponentRecord(String cpeId) {
		// Format Cpe Id and spilt by the colon.
		String formatCpe = cpeId.replace("/", "2.3:");
		String[] cpeComponents = formatCpe.split(":");

		ComponentsRecord swComponentRec = new ComponentsRecord();
		swComponentRec.setSwCpeId(formatCpe);
		swComponentRec.setSwPart(cpeComponents[2]);
		swComponentRec.setSwVendor(cpeComponents[3]);
		swComponentRec.setSwProduct(cpeComponents[4]);
		swComponentRec.setSwExternalRefs(externalRefsContent);

		// Check if version exists before accessing the index.
		if (cpeComponents.length > 5) {
			swComponentRec.setSwVersion(cpeComponents[5]);
		}

		SOFTWARE_COMPONENTS_RECORD.add(swComponentRec);

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
		Node riskFactorElement = reportItemElement.getElementsByTagName("risk_factor").item(0);
		Node exploitAvailableElement = reportItemElement.getElementsByTagName("exploit_available").item(0);

		setVulnRecord(cvssScoreElementNode, cveElement, cvssTempScoreElement, cvssTempVectorElement, cvssVectorElement, cweElement, recommedationElement,
				descriptionElement, publishedDateElement, riskFactorElement, exploitAvailableElement);

	}

	/**
	 * Creates Vuln Record, checks if an element exits & then adds it to vuln record
	 * list.
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
			Node cweElement, Node recommedationElement, Node descriptionElement, Node publishedDateElement, Node riskFactorElement, Node exploitAvailableElement) {

		VulnerabilitiesRecord vulnerabilityRecord = new VulnerabilitiesRecord();

		if (cvssScoreElementNode != null && cvssScoreElementNode.getNodeType() == Node.ELEMENT_NODE) {
			String cvssScore = cvssScoreElementNode.getTextContent();
			try {
				Double cvssScoreAsDouble = Double.parseDouble(cvssScore);
				vulnerabilityRecord.setCvssBaseScore(cvssScoreAsDouble);
			} catch (NumberFormatException e) {
				e.printStackTrace();
			}
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
			String cweID = cweElement.getTextContent();
			try {
				int cweIDvalue = Integer.parseInt(cweID);
				List<Integer> cweIDlist = new ArrayList<>();
				cweIDlist.add(cweIDvalue);
				vulnerabilityRecord.setCweID(cweIDlist);
			} catch (NumberFormatException e) {
				e.printStackTrace();
			}
		}
		if (recommedationElement != null && recommedationElement.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setRecommendation(recommedationElement.getTextContent());
		}
		if (descriptionElement != null && descriptionElement.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setDescription(descriptionElement.getTextContent());
		}
		if (publishedDateElement != null && publishedDateElement.getNodeType() == Node.ELEMENT_NODE) {
			String dateString = publishedDateElement.getTextContent();
			
			SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd");
			
			try {
				Date publishedDate = dateFormat.parse(dateString);
				vulnerabilityRecord.setPublishedDate(publishedDate);
			} catch (ParseException e) {
				e.printStackTrace();
			}

		}
		if (riskFactorElement != null && riskFactorElement.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setRiskFactor(riskFactorElement.getTextContent());
		}
		if (exploitAvailableElement != null && exploitAvailableElement.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setExploitAvailable(exploitAvailableElement.getTextContent());
		}

		
		VULNERABILITIES_RECORD.add(vulnerabilityRecord);
	}

	// Getter for record lists.
	public static List<ComponentsRecord> getComponentsRecord() {
		return SOFTWARE_COMPONENTS_RECORD;
	}

	public static List<VulnerabilitiesRecord> getVulnerabiltiesRecord() {
		return VULNERABILITIES_RECORD;
	}

}

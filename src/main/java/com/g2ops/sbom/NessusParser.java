package com.g2ops.sbom;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.cyclonedx.model.Dependency;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class NessusParser {

	private static final Logger LOGGER = Logger.getLogger(NessusParser.class.getName());
	private static final String CVE = "cve";
	private static final String CWE = "cwe";
	private static final String SCAN_INFO_PLUGIN_ID = "19506";
	private static final String WINDOWS_PLUGIN_ID = "20811";
	private static final String LINUX_PLUGIN_ID = "22869";

	private static List<ComponentsRecord> reportHostsList = new ArrayList<>();
	private static List<VulnerabilitiesRecord> vulnerabilitiesRecord = new ArrayList<>();
	private static Map<String, Set<String>> cveReportHostMap = new HashMap<>();
	private static Map<String, List<Dependency>> swInventoryHostMap = new HashMap<>();
	private static List<Dependency> dependenciesList;

	private static boolean continueExtraction = false;
	private static String cveToBeAdded = "";

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
			// Iterate over each ReportHost.
			for (int i = 0; i < reportHostList.getLength(); i++) {
				Node reportHostNode = reportHostList.item(i);

				if (reportHostNode.getNodeType() == Node.ELEMENT_NODE) {
					Element reportHostElement = (Element) reportHostNode;
					String reportHostName = reportHostElement.getAttribute("name");
					// Get Host Properties for each ReportHost.
					NodeList reportHostProperties = reportHostElement.getElementsByTagName("HostProperties");
					extractComponents(reportHostProperties);

					// Get all ReportItems for each ReportHost.
					NodeList reportItemList = reportHostElement.getElementsByTagName("ReportItem");
					extractVulnData(reportItemList, reportHostName);
					extractSoftwareData(reportItemList, reportHostName);
				}
			}

			// Build SBOMs.
			SbomBuilder.generateSBOM();

		} catch (ParserConfigurationException | SAXException | IOException e) {
			LOGGER.info("Exception thrown while parsing : " + e.getMessage());
		}

	}

	/**
	 * Extracts compoennt data from Report Hosts.
	 * 
	 * @param reportHostList
	 */
	private static void extractComponents(NodeList reportHostProperties) {

		// Get all Host Properties.
		Element hostPropertiesElement = (Element) reportHostProperties.item(0);

		// Check if the system-type tag exists.
		NodeList hostPropertiesTags = hostPropertiesElement.getElementsByTagName("tag");

		ComponentsRecord reportHostComponent = new ComponentsRecord();
		Map<Integer, String> cpeValues = new HashMap<>();

		// Loop through all tags under HostProperties.
		for (int j = 0; j < hostPropertiesTags.getLength(); j++) {
			Element tagElement = (Element) hostPropertiesTags.item(j);
			String tagName = tagElement.getAttribute("name");
			String tagValue = tagElement.getTextContent();

			// Set necesssary report hosts tags.
			if (tagName.equalsIgnoreCase("host-ip")) {
				reportHostComponent.setReportHostName(tagValue);
			}
			if (tagName.equalsIgnoreCase("system-type")) {
				reportHostComponent.setSystemType(tagValue);
			}
			if (tagName.equalsIgnoreCase("operating-system")) {
				reportHostComponent.setOperatingSystem(tagValue);
			}
			if (tagName.equalsIgnoreCase("mac-address")) {
				String macAddresses = tagValue.trim().replace("\n", ", ");
				reportHostComponent.setMacAddress(macAddresses);
			}
			if (tagName.startsWith("cpe")) {
				int cpeNumber = 0;
				// If there are more than one cpe attribute.
				if (tagName.contains("-")) {
					String[] tagNameParts = tagName.split("-");
					cpeNumber = Integer.parseInt(tagNameParts[1]);
					cpeValues.put(cpeNumber, tagValue);
				} else {
					reportHostComponent.setComponentCpe(conditionCpe(tagValue));
				}
			}
			// If only one cpe exists in cpeValues.
			if (cpeValues.size() == 1) {
				reportHostComponent.setComponentCpe(conditionCpe(cpeValues.values().iterator().next()));
				// More than one cpe exists in cpeValues.
			} else {
				int highestCpeNumber = 0;
				String highestCpeValue = null;
				for (Map.Entry<Integer, String> entry : cpeValues.entrySet()) {
					int cpeNumber = entry.getKey();
					if (cpeNumber > highestCpeNumber) {
						highestCpeNumber = cpeNumber;
						highestCpeValue = entry.getValue();
					}
				}
				if (highestCpeValue != null) {
					reportHostComponent.setComponentCpe(conditionCpe(highestCpeValue));
				}
			}

		}
		reportHostsList.add(reportHostComponent);

	}

	/**
	 * Takes CPE Id and conforms it to 2.3 specification.
	 * 
	 * @param cpeTagValue.
	 * @return conditionedCpe.
	 */
	private static String conditionCpe(String cpeTagValue) {
		String conditionedCpe = cpeTagValue.replace("/", "2.3:");
		return conditionedCpe;
	}

	/**
	 * Extracts vulnerability data from reportItem & saves it to vuln record.
	 * 
	 * @param reportItemElement , cvssScore Node.
	 */
	private static void extractVulnData(NodeList reportItemList, String reportHostName) {

		for (int i = 0; i < reportItemList.getLength(); i++) {
			Node reportItemNode = reportItemList.item(i);

			if (reportItemNode.getNodeType() == Node.ELEMENT_NODE) {
				Element reportItemElement = (Element) reportItemNode;
				NodeList childNodes = reportItemElement.getChildNodes();

				// Iterate over all child nodes.
				for (int j = 0; j < childNodes.getLength(); j++) {
					Node node = childNodes.item(j);

					// Check if the child node is a cve element.
					if (node.getNodeType() == Node.ELEMENT_NODE && node.getNodeName().equalsIgnoreCase(CVE)) {
						String cve = node.getTextContent().trim();
						// Check if CVE should be added to the SBOM.
						addCVE(cve, reportHostName);
					}
					
					// Get all other reportItems tag if new cve is found.
					if (continueExtraction) {
						
						// Extract CVEs. 
						NodeList cweNodes = reportItemElement.getElementsByTagName(CWE);
						Integer cweIDvalue = 0;
						for (int k=0; k < cweNodes.getLength(); k++) {
							Node cweNode = cweNodes.item(k);
							if (cweNode.getNodeType() == Node.ELEMENT_NODE) {
								String cweID = cweNode.getTextContent().trim();
								cweIDvalue = Integer.parseInt(cweID);
							}
							
							String reportItemPort = reportItemElement.getAttribute("port");
							String reportItemPluginName = reportItemElement.getAttribute("pluginName");
							Node cvssBaseScoreElement = reportItemElement.getElementsByTagName("cvss_base_score").item(0);
							Node cvssBaseVectorElement = reportItemElement.getElementsByTagName("cvss_vector").item(0);
							Node cvssTempScoreElement = reportItemElement.getElementsByTagName("cvss_temporal_score").item(0);
							Node cvssTempVectorElement = reportItemElement.getElementsByTagName("cvss_temporal_vector").item(0);
							Node recommedationElement = reportItemElement.getElementsByTagName("solution").item(0);
							Node descriptionElement = reportItemElement.getElementsByTagName("description").item(0);
							Node publishedDateElement = reportItemElement.getElementsByTagName("vuln_publication_date").item(0);
							Node riskFactorElement = reportItemElement.getElementsByTagName("risk_factor").item(0);
							Node exploitAvailableElement = reportItemElement.getElementsByTagName("exploit_available").item(0);
							
							createVulnRecord(cvssBaseScoreElement, cvssBaseVectorElement, cvssTempScoreElement, cvssTempVectorElement, recommedationElement,
									descriptionElement, publishedDateElement, riskFactorElement, exploitAvailableElement, cveToBeAdded, reportItemPort, cweIDvalue, reportItemPluginName);
						}



					}
					// Reset flag for the new new cve.
					continueExtraction = false;
				}

			}

		}

	}

	/**
	 * Checks the CVE found against the exisitng cveReportHost map.
	 * 
	 * @param cve            - cve id from the report item.
	 * @param reportHostName - host name the tag is found under.
	 */

	private static void addCVE(String cve, String reportHostName) {
		// Check if CVE is already in the map.
		if (cveReportHostMap.containsKey(cve)) {
			Set<String> reportHosts = cveReportHostMap.get(cve);
			// Check if the assocaited report host already exists.
			if (!reportHosts.contains(reportHostName)) {
				// If not, then add to the map.
				reportHosts.add(reportHostName);
			}

		} else {
			// If the CVE is new, add to the map and set extraction flag to true.
			Set<String> reportHosts = new HashSet<>();
			reportHosts.add(reportHostName);
			cveReportHostMap.put(cve, reportHosts);
			cveToBeAdded = cve;
			continueExtraction = true;
		}
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
	private static void createVulnRecord(Node cvssBaseScoreElement, Node cvssBaseVectorElement, Node cvssTempScoreElement, Node cvssTempVectorElement,
			Node recommedationElement, Node descriptionElement, Node publishedDateElement, Node riskFactorElement, Node exploitAvailableElement,
			 String cveToBeAdded, String reportItemPort, Integer cweIDvalue, String reportItemPluginName) {

		VulnerabilitiesRecord vulnerabilityRecord = new VulnerabilitiesRecord();

		vulnerabilityRecord.setCveID(cveToBeAdded);
		vulnerabilityRecord.setPort(reportItemPort);
		vulnerabilityRecord.setPluginName(reportItemPluginName);
		vulnerabilityRecord.setCweID(cweIDvalue);

		if (cvssBaseScoreElement != null && cvssBaseScoreElement.getNodeType() == Node.ELEMENT_NODE) {
			String cvssScore = cvssBaseScoreElement.getTextContent();
			try {
				Double cvssScoreAsDouble = Double.parseDouble(cvssScore);
				vulnerabilityRecord.setCvssBaseScore(cvssScoreAsDouble);
			} catch (NumberFormatException e) {
				e.printStackTrace();
			}
		}
		if (cvssTempScoreElement != null && cvssTempScoreElement.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setCvssTemporalScore(cvssTempScoreElement.getTextContent());

		}
		if (cvssTempVectorElement != null && cvssTempVectorElement.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setCvssTemporalVector(cvssTempVectorElement.getTextContent());
		}
		if (cvssBaseVectorElement != null && cvssBaseVectorElement.getNodeType() == Node.ELEMENT_NODE) {
			vulnerabilityRecord.setCvssVector(cvssBaseVectorElement.getTextContent());
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

		vulnerabilitiesRecord.add(vulnerabilityRecord);
	}

	/**
	 * Iterates through the Report Items and looks for plugins that output Software
	 * information.
	 * 
	 * @param reportItemList - List of Report Items for each Report Host.
	 * @param reportHostName - Report Host under which Report Items fall.
	 */

	private static void extractSoftwareData(NodeList reportItemList, String reportHostName) {

		for (int i = 0; i < reportItemList.getLength(); i++) {
			Node reportItemNode = reportItemList.item(i);

			if (reportItemNode.getNodeType() == Node.ELEMENT_NODE) {
				Element reportItemElement = (Element) reportItemNode;
				String pluginAttr = reportItemElement.getAttribute("pluginID");

				// Check for desired SW plugins & retrieve the plugin output.
				if (pluginAttr.equalsIgnoreCase(WINDOWS_PLUGIN_ID) || pluginAttr.equalsIgnoreCase(LINUX_PLUGIN_ID)) {
					Node pluginOutputNode = reportItemElement.getElementsByTagName("plugin_output").item(0);;;;;;;
					// Strip the plugin output off unncessary data.
					createSoftwareDependencies(pluginOutputNode, reportHostName); 
				}
			}
		}
	}


	/**
	 * Strips off unnceccary information and adds each software as a dependency to the Map. 
	 * 
	 * @param pluginOutput   - plugin output node content. 
	 * @param reportHostName - report host name. 
	 */
	private static void createSoftwareDependencies(Node pluginOutput, String reportHostName) {
		if (pluginOutput != null) {
			String outputText = pluginOutput.getTextContent().trim();

			// Remove unnecessary heading on top.
			outputText = outputText.replace("The following software are installed on the remote host :", "");
			// Remove lines containing "update"
	        outputText = outputText.replaceAll("(?i).*\\bupdate\\b.*\n", "");
	        // Remove content starting with "The following updates were installed"
	        outputText = outputText.replaceFirst("(?s)The following updates were installed.*?</plugin_output>", "");
	        
			String[] lines = outputText.split("\n");
			// Set to save unique SW enteries.
			List<Dependency> softwareList = new ArrayList<>();

			for (String line : lines) {
				line = line.trim();
				if (!line.isEmpty()) {
					// Remove SW installiation dates from the output, keep SW name & version. 
					String[] parts = line.split("\\[version");
					if (parts.length >= 2) {
						String software = parts[0].trim();
						// Check if the line contains "KB". if so, skip this line. 
						if (!software.contains("KB")) {
							String version = parts[1].split("\\]")[0].trim();
							// If the software name already contains the version info, then just add name. 
							Dependency swDependency;
							if (software.contains(version)) {
								swDependency = new Dependency(software);
								// Else, add software name + version. 
							} else {
								swDependency = new Dependency(software + " " + version);
							}
							softwareList.add(swDependency);								
						}
					}
				}
			}	
			// Add report host and assoicated sw list to the map & create dependencies. 
			swInventoryHostMap.put(reportHostName, softwareList);
			addSoftwareDependencies(swInventoryHostMap);
		}
	}

	/**
	 * Iterates through the SW inventory map and creates dependency objects based.
	 * @throws IOException 
	 * 
	 */
	private static void addSoftwareDependencies(Map<String, List<Dependency>> swInventoryHostMap) {
		// Initialize a new list empty list every time. 
		dependenciesList = new ArrayList<>();

		for (Map.Entry<String, List<Dependency>> entry : swInventoryHostMap.entrySet()) {
			String reportHostName = entry.getKey();
			List<Dependency> softwareList = entry.getValue();

			Dependency dependency = new Dependency(reportHostName);

			// If the software set is not empty.
			if (!softwareList.isEmpty()) {
				for (Dependency software : softwareList) {
					dependency.addDependency(software);
				}
			}
			dependenciesList.add(dependency);
		}
	}

	// Getters.
	public static List<VulnerabilitiesRecord> getVulnerabiltiesRecord() {
		return vulnerabilitiesRecord;
	}

	public static List<ComponentsRecord> getReportHostsList() {
		return reportHostsList;
	}

	public static Map<String, Set<String>> getCveReportHostMap() {
		return cveReportHostMap;
	}

	public static List<Dependency> getDependenciesList() {
		return dependenciesList;
	}

}

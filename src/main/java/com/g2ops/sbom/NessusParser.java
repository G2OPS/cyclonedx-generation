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

	private static List<ComponentsRecord> componentsList = new ArrayList<>();
	private static Set<String> uniqueCPEs = new HashSet<>();
	private static List<VulnerabilitiesRecord> vulnerabilitiesRecord = new ArrayList<>();
	private static Map<String, Set<String>> cveReportHostMap = new HashMap<>();
	private static Map<String, List<Dependency>> swInventoryHostMap = new HashMap<>();
	private static List<Dependency> dependenciesList;

	private static boolean continueExtraction = false;
	private static String cveToBeAdded = "";

	/**
	 * Reads NESSUS files and iterates through relevant data fields.
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
					NodeList tagList= reportHostElement.getElementsByTagName("tag");
					// extract relevant data. 
					extractCPEs(tagList);

					// TODO
					NodeList reportItemList = reportHostElement.getElementsByTagName("ReportItem");
					extractVulnData(reportItemList, null);
					extractSoftwareData(reportItemList, null);
				}
			}
			componentRecordInit(uniqueCPEs);
			SbomBuilder.generateSBOM();

		} catch (ParserConfigurationException | SAXException | IOException e) {
			LOGGER.info("Exception thrown while parsing : " + e.getMessage());
		}

	}

	/**
	 * Extracts CPE tag values.
	 * 
	 * @param tagList - NodeList of tags founds within a report host. 
	 */
	private static void extractCPEs(NodeList tagList) {

		for (int i = 0; i < tagList.getLength(); i++) {
			Node tagNode = tagList.item(i);
			
			if (tagNode.getNodeType() == Node.ELEMENT_NODE) {
				Element tagElement = (Element) tagNode;
				String tagName = tagElement.getAttribute("name");
				if (tagName != null && tagName.startsWith("cpe")) {
					String cpeName = tagElement.getTextContent().trim();
					uniqueCPEs.add(cpeName);		
					
				}
			}
		}
	}
	
	/**
	 * Creates a component record for each CPE found. 
	 * 
	 * @param cpeName - CPE name string. 
	 */
	private static void componentRecordInit(Set<String> uniqueCPEs) {
		
		for (String cpe : uniqueCPEs) {
			
			ComponentsRecord component = new ComponentsRecord();
			
			String[] cpeParts = cpe.split(":");
			component.setComponentCpe(cpe);
			component.setComponentName(getCpeName(cpeParts));
			component.setComponentType(getCpeType(cpeParts));
			component.setVendorName(getCpeVendor(cpeParts));
			component.setComponentVersion(getCpeVersion(cpeParts));
			
			componentsList.add(component);
		}
		
	}
	
	private static String getCpeVersion(String[] cpeParts) {
		String componentVersion;
		
		if(cpeParts.length > 4) {
			componentVersion = cpeParts[4];
		} else {
			componentVersion = "";
		}
		return componentVersion;
	}

	/**
	 * sets vendor based on CPE vendor name.
	 * 
	 * @param cpeParts - string [] spilt by CPE components.
	 * @return vendorName - CPE vendor to be set on component record. 
	 */
	private static String getCpeVendor(String[] cpeParts) {
		String cpeVendor = cpeParts[2];
		
		String vendorName;
		if (cpeVendor != null) {
			vendorName = cpeVendor;
		} else {
			vendorName = "";
		}
		return vendorName;
	}

	/**
	 * sets component type based on CPE part name. 
	 * 
	 * @param cpeParts - string [] spilt by CPE components.
	 * @return componentType - CPE type to be set on component record. 
	 */
	private static String getCpeType(String[] cpeParts) {
		String cpeType = cpeParts[1];
		
		String componentType = "";
		
		if (cpeType.equals("/o")) {
			componentType = "operating_system";
		} else if (cpeType.equals("/a")) {
			componentType = "application";
		}
		return componentType;
	}

	/**
	 * sets component name based on components available in a CPE. 
	 * 
	 * @param - string [] spilt by CPE components. 
	 * @return - cpeName - cpeName to be set on component record. 
	 */
	private static String getCpeName(String [] cpeParts) {
		String cpeName;
		if (cpeParts.length > 4 ) {
			// use product name & version. 
			cpeName = cpeParts[2] + "_" + cpeParts[3];
		} else if (cpeParts.length > 3) {
			// use only product name
			cpeName = cpeParts[3];
		} else {
			// use vendor
			cpeName = cpeParts[2];
		}
		return cpeName;
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

	public static List<ComponentsRecord> getComponentsList() {
		return componentsList;
	}

	public static Map<String, Set<String>> getCveReportHostMap() {
		return cveReportHostMap;
	}

	public static List<Dependency> getDependenciesList() {
		return dependenciesList;
	}

}

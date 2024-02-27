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

	private static final String CPE_PLUGIN = "Common Platform Enumeration (CPE)";
	private static final List<String> CPE_IDs = new ArrayList<>();
	private static final List<ComponentsRecord> COMPONENTS_RECORD = new ArrayList<>();

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

			// Get all elements by tag name.
			NodeList reportItemList = document.getElementsByTagName("ReportItem");
			// Flag to check if cpePlugin exits in the scan.
			boolean foundCpePlugin = false;

			for (int i = 0; i < reportItemList.getLength(); i++) {
				Node reportItemNode = reportItemList.item(i);

				if (reportItemNode.getNodeType() == Node.ELEMENT_NODE) {
					Element reportItemElement = (Element) reportItemNode;

					// Check if plugin name equals Common Platform Enumeration.
					String pluginName = reportItemElement.getAttribute("pluginName");
					if (CPE_PLUGIN.equalsIgnoreCase(pluginName)) {
						foundCpePlugin = true;
						// Extract plugin_output tag.
						Node pluginOutputNode = reportItemElement.getElementsByTagName("plugin_output").item(0);

						if (pluginOutputNode != null && pluginOutputNode.getNodeType() == Node.ELEMENT_NODE) {
							Element pluginOutputElement = (Element) pluginOutputNode;

							String pluginOutputContent = pluginOutputElement.getTextContent();
							extractCPE(pluginOutputContent);
						}
						// TODO Extract description tag.

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
				JOptionPane.showMessageDialog(null, "The selected Nessus scan did not the have the CPE plugin enabled.", "Info", JOptionPane.ERROR_MESSAGE);
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

	private static List<String> extractCPE(String pluginOutputContent) {

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

	public static List<ComponentsRecord> getComponentsRecord() {
		return COMPONENTS_RECORD;
	}
	
}

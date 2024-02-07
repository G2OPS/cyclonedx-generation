package com.g2ops.sbom;

import java.awt.HeadlessException;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JOptionPane;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class NessusParser {

	private static final Logger LOGGER = LogManager.getLogger();

	private static final String CPE_PLUGIN = "Common Platform Enumeration (CPE)";
	private static final List<String> CPE_IDs = new ArrayList<>();

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

			boolean foundCpePlugin = false;

			// Path to the nessus file(s).
			String desktopPath = System.getProperty("user.home") + "/OneDrive - G2 Ops, Inc/Desktop/";
			String logFilePath = desktopPath + "output_log.txt";

			try (PrintWriter writer = new PrintWriter(new FileWriter(logFilePath, true))) {
				for (int i = 0; i < reportItemList.getLength(); i++) {
					Node reportItemNode = reportItemList.item(i);

					if (reportItemNode.getNodeType() == Node.ELEMENT_NODE) {
						Element reportItemElement = (Element) reportItemNode;

						// Check if plugin name equals Common Platform Enumeration.
						String pluginFamily = reportItemElement.getAttribute("pluginName");
						if (CPE_PLUGIN.equalsIgnoreCase(pluginFamily)) {
							foundCpePlugin = true;

							Node pluginOutputNode = reportItemElement.getElementsByTagName("plugin_output").item(0);

							if (pluginOutputNode != null && pluginOutputNode.getNodeType() == Node.ELEMENT_NODE) {
								Element pluginOutputElement = (Element) pluginOutputNode;

								String pluginOutputContent = pluginOutputElement.getTextContent();
								extractCPE(pluginOutputContent);
							}
							// TODO
							// Condition CPE ID for proper standard. 
							// Store CPE values for each cpe component.
							// write stored values to the output file.

						}

					}

				}
				// Write to the output file.
				for (String cpeId : CPE_IDs) {
					writer.println(cpeId);
				}

				if (!foundCpePlugin) {
					writer.println("File: " + nessusFile.getName() + ", No CPE plugin found");
					JOptionPane.showMessageDialog(null, "The selected Nessus scan did not the have the CPE plugin enabled.", "Error",
							JOptionPane.ERROR_MESSAGE);
				}
			} catch (HeadlessException | DOMException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
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
			String formatCpe = cpeId.replace("/", "2.3:");
			
			// Check for duplicates before adding.
			if (!CPE_IDs.contains(formatCpe)) {
				CPE_IDs.add(formatCpe);
			}

			// Find the next occurrence of "cpe:" in the remaining content
			startIndex = pluginOutputContent.indexOf("cpe:", endIndex);
		}

		if (CPE_IDs.isEmpty()) {
			LOGGER.info("No cpe found in <plugin_output>");
		}
		return CPE_IDs;
	}
	
}

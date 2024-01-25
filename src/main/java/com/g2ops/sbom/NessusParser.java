package com.g2ops.sbom;

import java.awt.HeadlessException;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

import javax.swing.JOptionPane;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class NessusParser {

	private static final String PLUGIN_NAME = "Common Platform Enumeration (CPE)";

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

			String desktopPath = System.getProperty("user.home") + "/OneDrive - G2 Ops, Inc/Desktop/";
			String logFilePath = desktopPath + "output_log.txt";

			try (PrintWriter writer = new PrintWriter(new FileWriter(logFilePath, true))) {
				for (int i = 0; i < reportItemList.getLength(); i++) {
					Node reportItemNode = reportItemList.item(i);

					if (reportItemNode.getNodeType() == Node.ELEMENT_NODE) {
						Element reportItemElement = (Element) reportItemNode;

						// Check if plugin name equals Common Platform Enumeration.
						String pluginNameAttr = reportItemElement.getAttribute("pluginName");
						if (PLUGIN_NAME.equalsIgnoreCase(pluginNameAttr)) {
							foundCpePlugin = true;

							// Write to the output file.
							writer.println("File: " + nessusFile.getName() + ", Content: " + reportItemElement.getTextContent());
						}

					}

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

}

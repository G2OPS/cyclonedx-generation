package com.g2ops.sbom;

import java.io.IOException;
import java.io.InputStream;

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

	private static final String PLUGIN_NAME = "Common Platform Enumeration (CPE)";

	/**
	 * Reads nessus files and iterates through relevent data fields.
	 * 
	 * @param file input stream.
	 */

	public static void parseXML(InputStream inputStream) {
		try {
			DocumentBuilderFactory dbfactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dbuilder = dbfactory.newDocumentBuilder();
			Document document = dbuilder.parse(inputStream);

			// Remove any whitespace and structural irregularities.
			document.getDocumentElement().normalize();

			// Get all elements by tag name.
			NodeList reportItemList = document.getElementsByTagName("ReportItem");
			
			boolean foundCpePlugin = false;
			
			for (int i = 0; i < reportItemList.getLength(); i++) {
				Node reportItemNode = reportItemList.item(i);

				if (reportItemNode.getNodeType() == Node.ELEMENT_NODE) {
					Element reportItemElement = (Element) reportItemNode;

					// Check if plugin name equals Common Platform Enumeration.
					String pluginNameAttr = reportItemElement.getAttribute("pluginName");
					if (PLUGIN_NAME.equalsIgnoreCase(pluginNameAttr)) {
						foundCpePlugin = true;
						System.out.println(reportItemElement.getTextContent());
					}

				}

			}
			
			if(!foundCpePlugin) {
				JOptionPane.showMessageDialog(null,"The selected Nessus scan did not the have the CPE plugin enabled.", "Error", JOptionPane.ERROR_MESSAGE);
			}

		} catch (ParserConfigurationException | SAXException | IOException e) {
			e.printStackTrace();
		}

	}

}

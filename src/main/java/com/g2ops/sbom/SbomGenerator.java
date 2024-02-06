package com.g2ops.sbom;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class SbomGenerator {
	
	private static final Logger LOGGER = LogManager.getLogger();

	public static void main(String[] args) {
//		 Select nessus files.
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setFileFilter(new FileNameExtensionFilter("Nessus Files", "nessus"));
		fileChooser.setMultiSelectionEnabled(true);
		int numFiles = fileChooser.showOpenDialog(null);

		// Exit in case no file was selected.
		if (numFiles != JFileChooser.APPROVE_OPTION) {
			return;
		}

		// Extract data fields from selected files.
		File[] nessusFiles = fileChooser.getSelectedFiles();

		for (File nessusFile : nessusFiles) {

			LOGGER.info("Processing File Name: " + nessusFile.getName());

			try (InputStream inputStream = Files.newInputStream(nessusFile.toPath())) {
				NessusParser.parseXML(inputStream, nessusFile);

			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

}
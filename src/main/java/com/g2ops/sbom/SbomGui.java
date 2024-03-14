package com.g2ops.sbom;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.util.logging.Logger;


public class SbomGui {
	
	private static final Logger LOGGER = Logger.getLogger(SbomGui.class.getName());

	public static void main(String[] args) {
		
//		Set default directory path & select Nessus file(s).
		JFileChooser fileChooser = new JFileChooser();
		String userDesktopPath = System.getProperty("user.home") + File.separator + "OneDrive - G2 Ops, Inc/Desktop";
		fileChooser.setCurrentDirectory(new File(userDesktopPath));
		
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
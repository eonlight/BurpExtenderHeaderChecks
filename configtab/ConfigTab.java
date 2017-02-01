package configtab;

import java.awt.Component;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

import javax.swing.GroupLayout;
import javax.swing.GroupLayout.ParallelGroup;
import javax.swing.GroupLayout.SequentialGroup;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.LayoutStyle;
import javax.swing.table.DefaultTableModel;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.ITab;
import staterestorer.StateRestorer;
import versionchecker.BurpIO;
import versionchecker.VersionChecker;
import versionchecker.VersionConfig;

public class ConfigTab implements ITab {

	private static final int HEADER_SIZE = 17;
	private static final int MSG_SIZE = 12;
	private static final int LABEL_SIZE = 14;
	private static final int BUTTON_SIZE = 100;

	private JPanel tab;
	private IBurpExtenderCallbacks callbacks;
	
	private static final String NAME = "Configuration Tab";
	private static final String VERSION = "0.2.3";
	
	public ConfigTab(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
		this.callbacks = callbacks;
		this.initGui();
		
		BurpIO.getInstance().write("[*] Loaded " + NAME + " v" + VERSION);
	}
	
	private void initGui(){		
		this.tab = new JPanel();
		
		GroupLayout layout = new GroupLayout(this.tab); 
		this.tab.setLayout(layout);
		
		layout.setAutoCreateGaps(true);
		layout.setAutoCreateContainerGaps(true);
		
		/* State Restorer Layout Creation */
		
		// State restorer components
		final JLabel stateRestorerMsg  = new JLabel();
		stateRestorerMsg.setFont(new Font("Tahoma", 1, MSG_SIZE));
		
		JLabel stateRestorerLabel = new JLabel("State Restorer Settings");
		stateRestorerLabel.setFont(new Font("Tahoma", 1, HEADER_SIZE));
		
		final JTextField stateRestorerPathText = new JTextField(StateRestorer.path);
		stateRestorerPathText.addFocusListener(new FocusListener() {
			@Override
			public void focusLost(FocusEvent e) {
				if(!stateRestorerPathText.getText().equals(StateRestorer.path)){
					StateRestorer.path = stateRestorerPathText.getText();
					callbacks.saveExtensionSetting("StateRestorerPath", StateRestorer.path);
					stateRestorerMsg.setText("State Restorer Path saved: " + StateRestorer.path);
				}
			}
			
			@Override
			public void focusGained(FocusEvent e) {
				// Nothing to do when focus is gained
			}
		});
		
		JButton stateRestorerChooseFileButton = new JButton("Choose File");
		stateRestorerChooseFileButton.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent event) {
				JFileChooser chooseFile = new JFileChooser();
				int ret = chooseFile.showDialog(tab, "Choose a file");
				
				if(ret == JFileChooser.APPROVE_OPTION){
					File file = chooseFile.getSelectedFile();
					try {
						StateRestorer.path = file.getCanonicalPath();
					} catch (IOException e) {
						if(BurpExtender.DEBUG)
							e.printStackTrace(BurpIO.getInstance().stderr);
						StateRestorer.path = StateRestorer.DEFAULT_PATH;
					}
					
					callbacks.saveExtensionSetting("StateRestorerPath", StateRestorer.path);
					stateRestorerMsg.setText("State Restorer Path saved: " + StateRestorer.path);					
					stateRestorerPathText.setText(StateRestorer.path);
				}
				            
			}
		});
		
		final JCheckBox stateRestorerActiveCheckBox = new JCheckBox("Activate the automatic state restorer on burp startup.");
		stateRestorerActiveCheckBox.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if(stateRestorerActiveCheckBox.isSelected()){
					StateRestorer.active = true;
					callbacks.saveExtensionSetting("stateRestorerActive", "true");
					stateRestorerMsg.setText("Default state on " + StateRestorer.path + " will be loaded on burp startup.");
				} else { 
					StateRestorer.active = false;
					callbacks.saveExtensionSetting("stateRestorerActive", "false");
					stateRestorerMsg.setText("Default state on " + StateRestorer.path + " won't be loaded on burp startup.");
				}
			}
		});
		
		String activeSetting = callbacks.loadExtensionSetting("stateRestorerActive");
		StateRestorer.active = !(activeSetting != null && activeSetting.equals("false"));
		stateRestorerActiveCheckBox.setSelected(StateRestorer.active);
		
		JButton stateRestorerResetPathButton = new JButton("Reset Path");
		stateRestorerResetPathButton.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent event) {
				StateRestorer.path = StateRestorer.DEFAULT_PATH;
				stateRestorerPathText.setText(StateRestorer.path);
				callbacks.saveExtensionSetting("StateRestorerPath", StateRestorer.path);
				stateRestorerMsg.setText("State Restorer Path saved: " + StateRestorer.path);
			}
		});
		
		JLabel stateRestorerTextLabel = new JLabel("Burp State File: ");
		stateRestorerTextLabel.setFont(new Font("Tahoma", 1, LABEL_SIZE));
		
		// Setting layout groups
		ParallelGroup stateRestorerHorizontalLayout = layout.createParallelGroup(GroupLayout.Alignment.LEADING)
				.addComponent(stateRestorerLabel)
				.addGroup(layout.createSequentialGroup()
						.addComponent(stateRestorerTextLabel)
						.addComponent(stateRestorerPathText)
						.addComponent(stateRestorerChooseFileButton)
						.addComponent(stateRestorerResetPathButton)
				)
				.addComponent(stateRestorerActiveCheckBox)
				.addComponent(stateRestorerMsg);

		SequentialGroup stateRestorerVertialLayout = layout.createSequentialGroup()
				.addComponent(stateRestorerLabel)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
						.addComponent(stateRestorerTextLabel)
						.addComponent(stateRestorerPathText)
						.addComponent(stateRestorerChooseFileButton)
						.addComponent(stateRestorerResetPathButton)
				)
				.addComponent(stateRestorerActiveCheckBox)
				.addComponent(stateRestorerMsg);
		
		/* Information Disclosure Headers Layout */
		
		// Information Disclosure Components
		final JLabel infoDisclosureMsg  = new JLabel();
		infoDisclosureMsg.setFont(new Font("Tahoma", 1, MSG_SIZE));
		
		JLabel infoDisclosureLabel = new JLabel("Information Disclosure Headers Settings");
		infoDisclosureLabel.setFont(new Font("Tahoma", 1, HEADER_SIZE));
		
		
		JScrollPane infoDisclosureHeadersPane = new JScrollPane();
		final JList<String> infoDisclosureHeadersList = new JList<String>();
		infoDisclosureHeadersPane.setViewportView(infoDisclosureHeadersList);
		infoDisclosureHeadersList.setListData(VersionChecker.searchHeaders);
		
		JButton infoDisclosureLoadButton = new JButton("Load");
		infoDisclosureLoadButton.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent event) {
				JFileChooser chooseFile = new JFileChooser();
				int ret = chooseFile.showDialog(tab, "Choose a file");
				
				if(ret == JFileChooser.APPROVE_OPTION){
					File file = chooseFile.getSelectedFile();
					
					ArrayList<String> newHeaders = new ArrayList<String>();
					
					try {
						BufferedReader reader = new BufferedReader(new FileReader(file));
						String line = reader.readLine();
						while(line != null){
							newHeaders.add(line);
							line = reader.readLine();
						}
						reader.close();
						infoDisclosureMsg.setText("Loaded Headers From: " + file.getAbsolutePath());	
					} catch (IOException e) {
						if(BurpExtender.DEBUG)
							e.printStackTrace(BurpIO.getInstance().stderr);
						infoDisclosureMsg.setText("Error when loading the headers from the file.");	
					}
					
					for(String header : VersionChecker.searchHeaders)
						newHeaders.add(header);
					VersionChecker.searchHeaders = (String[]) newHeaders.toArray();
					
					VersionChecker.saveCurrentInfoDisclosureHeaders(callbacks);
				}
			}
		});
		
		JButton infoDisclosureRemoveButton = new JButton("Remove");
		infoDisclosureRemoveButton.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent event) {
				int selected = infoDisclosureHeadersList.getSelectedIndex();
				
				String[] newHeaders = new String[VersionChecker.searchHeaders.length - 1];
				for(int i = 0, j = 0; i < VersionChecker.searchHeaders.length; i++){
					if(i != selected)
						newHeaders[j++] = VersionChecker.searchHeaders[i];
					else
						infoDisclosureMsg.setText("Information disclosure Header Removed: " + VersionChecker.searchHeaders[i]);		 
				}
				
				VersionChecker.searchHeaders = newHeaders;
				infoDisclosureHeadersList.setListData(VersionChecker.searchHeaders);
				VersionChecker.saveCurrentInfoDisclosureHeaders(callbacks);
			}
		});
		
		JButton infoDisclosureResetButton = new JButton("Reset");
		infoDisclosureResetButton.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent event) {
				VersionChecker.searchHeaders = VersionChecker.getDefaultInfoDisclosureHeaders();
				infoDisclosureHeadersList.setListData(VersionChecker.searchHeaders);
				infoDisclosureMsg.setText("Information Disclosure Headers Reset to the Default ones.");	
				VersionChecker.saveCurrentInfoDisclosureHeaders(callbacks);
			}
		});
		
		
		final JTextField infoDisclosureNewHeaderText = new JTextField("New Header...");
		infoDisclosureNewHeaderText.addFocusListener(new FocusListener() {
			@Override
			public void focusLost(FocusEvent e) {
				if(infoDisclosureNewHeaderText.getText().equals(""))
					infoDisclosureNewHeaderText.setText("New Header...");
			}
			
			@Override
			public void focusGained(FocusEvent e) {
				infoDisclosureNewHeaderText.setText("");
			}
		});

		JButton infoDisclosureAddButton = new JButton("Add");
		infoDisclosureAddButton.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent event) {
				String[] newHeaders = new String[VersionChecker.searchHeaders.length + 1];
				for(int i = 0; i < VersionChecker.searchHeaders.length; i++)
					newHeaders[i+1] = VersionChecker.searchHeaders[i];
				newHeaders[0] = infoDisclosureNewHeaderText.getText();
				VersionChecker.searchHeaders = newHeaders;
				infoDisclosureHeadersList.setListData(VersionChecker.searchHeaders);
				infoDisclosureMsg.setText("Information disclosure Header Added: " + infoDisclosureNewHeaderText.getText());
				VersionChecker.saveCurrentInfoDisclosureHeaders(callbacks);
			}
		});
		
		// setting info disclosure layout
		ParallelGroup infoDisclosureHorizontalLayout = layout.createParallelGroup(GroupLayout.Alignment.LEADING)
				.addComponent(infoDisclosureLabel)
				.addGroup(layout.createSequentialGroup()
						.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
								.addComponent(infoDisclosureLoadButton, GroupLayout.PREFERRED_SIZE, BUTTON_SIZE, GroupLayout.PREFERRED_SIZE)
								.addComponent(infoDisclosureRemoveButton, GroupLayout.PREFERRED_SIZE, BUTTON_SIZE, GroupLayout.PREFERRED_SIZE)
								.addComponent(infoDisclosureResetButton, GroupLayout.PREFERRED_SIZE, BUTTON_SIZE, GroupLayout.PREFERRED_SIZE)
						)
						.addComponent(infoDisclosureHeadersPane)
				)
				.addGroup(layout.createSequentialGroup()
						.addComponent(infoDisclosureAddButton, GroupLayout.PREFERRED_SIZE, BUTTON_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(infoDisclosureNewHeaderText)
				)
				.addComponent(infoDisclosureMsg);
	
		//.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
		
		SequentialGroup infoDisclosureVerticalLayout = layout.createSequentialGroup()
				.addComponent(infoDisclosureLabel)
				.addGroup(layout.createParallelGroup()
						.addGroup(layout.createSequentialGroup()
								.addComponent(infoDisclosureLoadButton)
								.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(infoDisclosureRemoveButton)
								.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(infoDisclosureResetButton)
						)
						.addComponent(infoDisclosureHeadersPane, GroupLayout.PREFERRED_SIZE, 138, GroupLayout.PREFERRED_SIZE)
				)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
						.addComponent(infoDisclosureAddButton)
						.addComponent(infoDisclosureNewHeaderText)
				)
				.addComponent(infoDisclosureMsg);
		
		/* Missing Security Headers Layout */
		
		// Missing Headers Components
		final JLabel missingHeadersMsg  = new JLabel();
		missingHeadersMsg.setFont(new Font("Tahoma", 1, MSG_SIZE));
		
		JLabel missingHeadersLabel = new JLabel("Missing Security Headers Settings");
		missingHeadersLabel.setFont(new Font("Tahoma", 1, HEADER_SIZE));
		
		JScrollPane missingHeadersPane = new JScrollPane();
		final JList<String> missingHeadersList = new JList<String>();
		missingHeadersPane.setViewportView(missingHeadersList);
		missingHeadersList.setListData(VersionChecker.missingHeaders);
		
		JButton missingHeadersLoadButton = new JButton("Load");
		missingHeadersLoadButton.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent event) {
				JFileChooser chooseFile = new JFileChooser();
				int ret = chooseFile.showDialog(tab, "Choose a file");
				
				if(ret == JFileChooser.APPROVE_OPTION){
					File file = chooseFile.getSelectedFile();
					
					ArrayList<String> newHeaders = new ArrayList<String>();
					
					try {
						BufferedReader reader = new BufferedReader(new FileReader(file));
						String line = reader.readLine();
						while(line != null){
							newHeaders.add(line);
							line = reader.readLine();
						}
						reader.close();
						missingHeadersMsg.setText("Loaded Headers From: " + file.getAbsolutePath());	
					} catch (IOException e) {
						if(BurpExtender.DEBUG)
							e.printStackTrace(BurpIO.getInstance().stderr);
						missingHeadersMsg.setText("Error when loading the headers from the file.");	
					}
					
					for(String header : VersionChecker.missingHeaders)
						newHeaders.add(header);
					VersionChecker.missingHeaders = (String[]) newHeaders.toArray();
					
					VersionChecker.saveCurrentMissingHeaders(callbacks);
				}
			}
		});
		
		final JButton missingHeadersRemoveButton = new JButton("Remove");
		missingHeadersRemoveButton.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent event) {
				int selected = missingHeadersList.getSelectedIndex();
				
				String[] newHeaders = new String[VersionChecker.missingHeaders.length - 1];
				for(int i = 0, j = 0; i < VersionChecker.missingHeaders.length; i++){
					if(i != selected)
						newHeaders[j++] = VersionChecker.missingHeaders[i];
					else
						missingHeadersMsg.setText("Missing Header Removed: " + VersionChecker.missingHeaders[i]);		 
				}
				
				VersionChecker.missingHeaders = newHeaders;
				missingHeadersList.setListData(VersionChecker.missingHeaders);

				VersionChecker.saveCurrentMissingHeaders(callbacks);
			}
		});
		
		JButton missingHeadersResetButton = new JButton("Reset");
		missingHeadersResetButton.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent event) {
				VersionChecker.missingHeaders = VersionChecker.getDefaultMissingHeaders();
				missingHeadersList.setListData(VersionChecker.missingHeaders);
				missingHeadersMsg.setText("Missing Security Headers Reset to the Default ones.");
				VersionChecker.saveCurrentMissingHeaders(callbacks);
			}
		});
		
		
		final JTextField missingHeadersNewHeaderText = new JTextField("New Header...");
		missingHeadersNewHeaderText.addFocusListener(new FocusListener() {
			@Override
			public void focusLost(FocusEvent e) {
				if(missingHeadersNewHeaderText.getText().equals(""))
					missingHeadersNewHeaderText.setText("New Header...");
			}
			
			@Override
			public void focusGained(FocusEvent e) {
				missingHeadersNewHeaderText.setText("");
			}
		});

		JButton missingHeadersAddButton = new JButton("Add");
		missingHeadersAddButton.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent event) {
				String[] newHeaders = new String[VersionChecker.missingHeaders.length + 1];
				for(int i = 0; i < VersionChecker.missingHeaders.length; i++)
					newHeaders[i+1] = VersionChecker.missingHeaders[i];
				newHeaders[0] = missingHeadersNewHeaderText.getText();
				VersionChecker.missingHeaders = newHeaders;
				missingHeadersList.setListData(VersionChecker.missingHeaders);
				missingHeadersMsg.setText("Missing Security Header Added: " + missingHeadersNewHeaderText.getText());
				VersionChecker.saveCurrentMissingHeaders(callbacks);
			}
		});
		
		final JCheckBox additionalIssueMissingHeadersFound = new JCheckBox("Add an Information Issue when these headers are found");
		additionalIssueMissingHeadersFound.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if(additionalIssueMissingHeadersFound.isSelected()){
					VersionChecker.additionalInfoIssue = true;
					callbacks.saveExtensionSetting("additionalInfoIssue", "true");
					missingHeadersMsg.setText("Missing Security Header Found Informational Issue will be added");
				} else { 
					VersionChecker.additionalInfoIssue = false;
					callbacks.saveExtensionSetting("additionalInfoIssue", "false");
					missingHeadersMsg.setText("Missing Security Header Found Informational Issue won't be added");
				}
			}
		});
		
		additionalIssueMissingHeadersFound.setSelected(VersionChecker.additionalInfoIssue);
		
		// setting missing headers layout
		ParallelGroup missingHeadersHorizontalLayout = layout.createParallelGroup(GroupLayout.Alignment.LEADING)
				.addComponent(missingHeadersLabel)
				.addGroup(layout.createSequentialGroup()
						.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
								.addComponent(missingHeadersLoadButton, GroupLayout.PREFERRED_SIZE, BUTTON_SIZE, GroupLayout.PREFERRED_SIZE)
								.addComponent(missingHeadersRemoveButton, GroupLayout.PREFERRED_SIZE, BUTTON_SIZE, GroupLayout.PREFERRED_SIZE)
								.addComponent(missingHeadersResetButton, GroupLayout.PREFERRED_SIZE, BUTTON_SIZE, GroupLayout.PREFERRED_SIZE)
						)
						.addComponent(missingHeadersPane)
				)
				.addGroup(layout.createSequentialGroup()
						.addComponent(missingHeadersAddButton, GroupLayout.PREFERRED_SIZE, BUTTON_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(missingHeadersNewHeaderText)
				)
				.addComponent(additionalIssueMissingHeadersFound)
				.addComponent(missingHeadersMsg);
			
		SequentialGroup missingHeadersVerticalLayout = layout.createSequentialGroup()
				.addComponent(missingHeadersLabel)
				.addGroup(layout.createParallelGroup()
						.addGroup(layout.createSequentialGroup()
								.addComponent(missingHeadersLoadButton)
								.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(missingHeadersRemoveButton)
								.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(missingHeadersResetButton)
						)
						.addComponent(missingHeadersPane, GroupLayout.PREFERRED_SIZE, 138, GroupLayout.PREFERRED_SIZE)
				)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
						.addComponent(missingHeadersAddButton)
						.addComponent(missingHeadersNewHeaderText)
				)
				.addComponent(additionalIssueMissingHeadersFound)
				.addComponent(missingHeadersMsg);
		
		/* Version Checker Layout */
		
		// Version Checker Components
		final JLabel versionCheckerMsg  = new JLabel();
		versionCheckerMsg.setFont(new Font("Tahoma", 1, MSG_SIZE));
		
		JLabel versionCheckerLabel = new JLabel("Version Checker Settings");
		versionCheckerLabel.setFont(new Font("Tahoma", 1, HEADER_SIZE));
		
		final String [] columnNames = new String[]{"ID", "Software", "URL", "Regex", "CVEs"};
		
		final DefaultTableModel versionCheckerTableModel = new DefaultTableModel(BurpIO.getInstance().getVersionConfigs(), columnNames);
		versionCheckerTableModel.addTableModelListener(new TableModelListener() {
			@Override
			public void tableChanged(TableModelEvent e) {
				if(e.getType() == TableModelEvent.UPDATE){
					int row = e.getLastRow();
					if(row != -1){
						int id = Integer.parseInt((String) versionCheckerTableModel.getValueAt(row, 0));
						String url = (String) versionCheckerTableModel.getValueAt(row, 2);
						String regex = (String) versionCheckerTableModel.getValueAt(row, 3);
						String cves = (String) versionCheckerTableModel.getValueAt(row, 4);
						VersionConfig config = BurpIO.getInstance().getVersionConfig(id);
						
						config.url = url;
						config.regex = regex;
						config.cves = cves;
						versionCheckerTableModel.setValueAt(config.software, row, 1);
						
						versionCheckerMsg.setText("Version Checker Configuration changed for: " + config.software);
						
						BurpIO.getInstance().saveCurrentVersionCheckerConfigs();
					}
				}
			}
		});
		
		final JTable versionCheckerTable = new JTable(versionCheckerTableModel);
		versionCheckerTable.removeColumn(versionCheckerTable.getColumnModel().getColumn(0));
		JScrollPane versionCheckerTableContainer = new JScrollPane(versionCheckerTable);
		
				
		JButton versionCheckerRemoveButton = new JButton("Remove");
		versionCheckerRemoveButton.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent event) {
				int selected = versionCheckerTable.getSelectedRow();
				int id = Integer.parseInt((String) versionCheckerTableModel.getValueAt(selected, 0));
				VersionConfig config = BurpIO.getInstance().removeConfig(id);
				versionCheckerTableModel.removeRow(selected);
				
				versionCheckerMsg.setText("Software Configuration Removed: " + config.software);
				
				BurpIO.getInstance().saveCurrentVersionCheckerConfigs();
			}
		});
		
		JButton versionCheckerResetButton = new JButton("Reset");
		versionCheckerResetButton.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent event) {
				BurpIO.getInstance().resetConfig();
				for(int i = 0; i < versionCheckerTableModel.getRowCount(); i++)
					versionCheckerTableModel.removeRow(i);
				versionCheckerTableModel.setDataVector(BurpIO.getInstance().getVersionConfigs(), columnNames);
				versionCheckerTable.removeColumn(versionCheckerTable.getColumnModel().getColumn(0));
				versionCheckerMsg.setText("Software Configuration Defaults Restored");
				
				BurpIO.getInstance().saveCurrentVersionCheckerConfigs();
			}
		});
		
		final JTextField versionCheckerNewSoftwareText = new JTextField("New Software...");
		versionCheckerNewSoftwareText.addFocusListener(new FocusListener() {
			@Override
			public void focusLost(FocusEvent e) {
				if(versionCheckerNewSoftwareText.getText().equals(""))
					versionCheckerNewSoftwareText.setText("New Software...");
			}
			
			@Override
			public void focusGained(FocusEvent e) {
				versionCheckerNewSoftwareText.setText("");
			}
		});
		
		final JTextField versionCheckerNewURLText = new JTextField("New URL...");
		versionCheckerNewURLText.addFocusListener(new FocusListener() {
			@Override
			public void focusLost(FocusEvent e) {
				if(versionCheckerNewURLText.getText().equals(""))
					versionCheckerNewURLText.setText("New URL...");
			}
			
			@Override
			public void focusGained(FocusEvent e) {
				versionCheckerNewURLText.setText("");
			}
		});
		
		final JTextField versionCheckerNewRegexText = new JTextField("New Regex...");
		versionCheckerNewRegexText.addFocusListener(new FocusListener() {
			@Override
			public void focusLost(FocusEvent e) {
				if(versionCheckerNewRegexText.getText().equals(""))
					versionCheckerNewRegexText.setText("New Regex...");
			}
			
			@Override
			public void focusGained(FocusEvent e) {
				versionCheckerNewRegexText.setText("");
			}
		});
		
		final JTextField versionCheckerNewCVEText = new JTextField("New CVE URL...");
		versionCheckerNewCVEText.addFocusListener(new FocusListener() {
			@Override
			public void focusLost(FocusEvent e) {
				if(versionCheckerNewCVEText.getText().equals(""))
					versionCheckerNewCVEText.setText("New CVE URL...");
			}
			
			@Override
			public void focusGained(FocusEvent e) {
				versionCheckerNewCVEText.setText("");
			}
		});
		
		JButton versionCheckerAddButton = new JButton("Add");
		versionCheckerAddButton.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent event) {
				String newSoftware = versionCheckerNewSoftwareText.getText();
				String newURL = versionCheckerNewURLText.getText();
				String newRegex = versionCheckerNewRegexText.getText();
				String newCVE = versionCheckerNewCVEText.getText();
				
				VersionConfig config = BurpIO.getInstance().addVersionConfig(newSoftware, newURL, newRegex, newCVE);
				if(config == null){
					versionCheckerMsg.setText("Software Configuration for " + newSoftware + " already exists.");
				} else {
					versionCheckerTableModel.addRow(new String[]{"" + config.id, config.software, config.url, config.regex, config.cves});
					versionCheckerMsg.setText("Software Configuration Added for: " + config.software);
					BurpIO.getInstance().saveCurrentVersionCheckerConfigs();
				}
			}
		});
		
		// setting missing headers layout
		ParallelGroup versionCheckerHorizontalLayout = layout.createParallelGroup(GroupLayout.Alignment.LEADING)
				.addComponent(versionCheckerLabel)
				.addGroup(layout.createSequentialGroup()
						.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
								.addComponent(versionCheckerRemoveButton, GroupLayout.PREFERRED_SIZE, BUTTON_SIZE, GroupLayout.PREFERRED_SIZE)
								.addComponent(versionCheckerResetButton, GroupLayout.PREFERRED_SIZE, BUTTON_SIZE, GroupLayout.PREFERRED_SIZE)
						)
						.addComponent(versionCheckerTableContainer)
				)
				.addGroup(layout.createSequentialGroup()
						.addComponent(versionCheckerAddButton, GroupLayout.PREFERRED_SIZE, BUTTON_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(versionCheckerNewSoftwareText)
						.addComponent(versionCheckerNewURLText)
						.addComponent(versionCheckerNewRegexText)
						.addComponent(versionCheckerNewCVEText)
				)
				.addComponent(versionCheckerMsg);
			
		SequentialGroup versionCheckerVerticalLayout = layout.createSequentialGroup()
				.addComponent(versionCheckerLabel)
				.addGroup(layout.createParallelGroup()
						.addGroup(layout.createSequentialGroup()
								.addComponent(versionCheckerRemoveButton)
								.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(versionCheckerResetButton)
						)
						.addComponent(versionCheckerTableContainer, GroupLayout.PREFERRED_SIZE, 138, GroupLayout.PREFERRED_SIZE)
				)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
						.addComponent(versionCheckerAddButton)
						.addComponent(versionCheckerNewSoftwareText)
						.addComponent(versionCheckerNewURLText)
						.addComponent(versionCheckerNewRegexText)
						.addComponent(versionCheckerNewCVEText)
				)
				.addComponent(versionCheckerMsg);
			
		/* Check if any configuration was saved previously and update the Tab */
		String aditionalInfoIssue = callbacks.loadExtensionSetting("aditionalInfoIssue");
		if(aditionalInfoIssue != null && aditionalInfoIssue.equals("true")){
			VersionChecker.additionalInfoIssue = true;
			additionalIssueMissingHeadersFound.setSelected(true);
		}

		/* Final Layout */
		
		layout.setHorizontalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
				.addGap(20, 20, 20)
				.addGroup(stateRestorerHorizontalLayout)
				.addGap(20, 20, 20)
				.addGroup(infoDisclosureHorizontalLayout)
				.addGap(20, 20, 20)
				.addGroup(missingHeadersHorizontalLayout)
				.addGap(20, 20, 20)
				.addGroup(versionCheckerHorizontalLayout)
		);
		
		layout.setVerticalGroup(layout.createSequentialGroup()
				.addGap(20, 20, 20)
				.addGroup(stateRestorerVertialLayout)
				.addGap(20, 20, 20)
				.addGroup(infoDisclosureVerticalLayout)
				.addGap(20, 20, 20)
				.addGroup(missingHeadersVerticalLayout)
				.addGap(20, 20, 20)
				.addGroup(versionCheckerVerticalLayout)
		);
		
	}
	
	@Override
	public String getTabCaption() {
		return "Burp Extender Config";
	}

	@Override
	public Component getUiComponent() {
		return this.tab;
	}

}

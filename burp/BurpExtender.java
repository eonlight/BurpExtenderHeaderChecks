package burp;

import configtab.ConfigTab;
import jsondecoder.JsonDecoder;
import staterestorer.StateRestorer;

import versionchecker.BurpIO;
import versionchecker.VersionChecker;

public class BurpExtender implements IBurpExtender {
	
	public static final boolean DEBUG = false;
	
	private static final String NAME = "Additional Header Checks & Burp Helpers";
	private static final String VERSION = "0.3.3";
		
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {		
		// Always needs to go first
		BurpIO.createInstance(callbacks);
		
		StateRestorer.loadState(callbacks);
		
		callbacks.setExtensionName(NAME);
		
		// Load Functionalities
		callbacks.registerScannerCheck(new VersionChecker(callbacks, callbacks.getHelpers()));
		callbacks.registerMessageEditorTabFactory(new JsonDecoder(callbacks, callbacks.getHelpers()));
		callbacks.addSuiteTab(new ConfigTab(callbacks, callbacks.getHelpers()));
		
		BurpIO.getInstance().write("[*] Loaded Extension " + NAME + " v" + VERSION + " (C) Ruben de Campos");
	}
}
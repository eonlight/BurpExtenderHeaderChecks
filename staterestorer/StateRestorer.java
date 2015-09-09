package staterestorer;

import java.io.File;

import burp.IBurpExtenderCallbacks;
import versionchecker.BurpIO;

public class StateRestorer {
	
	public static final String DEFAULT_PATH = System.getenv("HOME") + "/.java/.userPrefs/burp/userSavedState";
	public static String path = DEFAULT_PATH;
	
	public static boolean active = true;
	
	public static void loadState(IBurpExtenderCallbacks callbacks){
		String savedPath = callbacks.loadExtensionSetting("StateRestorerPath");
		if(savedPath != null)
			path = savedPath;
		
		// Replaces the ~ for the user's home
		if(path.startsWith("~"))
			path = path.replaceFirst("~", System.getenv("HOME"));
				
		String activeSetting = callbacks.loadExtensionSetting("stateRestorerActive");
		active = !(activeSetting != null && activeSetting.equals("false"));
		
		if(active){
			File state = new File(path);
			if(state != null && state.exists()){
				BurpIO.getInstance().write("[*] State Restored");
				callbacks.restoreState(state);	
			} else
				BurpIO.getInstance().error("[*] State File Not Found In: " + path);
		}

	}

}

package versionchecker;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VersionFinding {

	public static final Pattern versionRegex = Pattern.compile("(\\d+\\.?)+");
	public static final Pattern nameRegex = Pattern.compile("[a-zA-Z0-9\\-\\.]+");

	private String version;
	private String software;
	private boolean outdated;
	private String error = null;
	private String latest;
	private int ID;
	
	public VersionFinding(String software, String version){
		this.software = software;
		
		Matcher nameMatcher = nameRegex.matcher(software);
		if(nameMatcher.find())
			this.software = nameMatcher.group(0);
		
		this.version = null;
		Matcher versionMatcher = versionRegex.matcher(version);
		if(versionMatcher.find())
			this.version = versionMatcher.group(0);
		
		this.ID = this.software.toLowerCase().hashCode();
		
		this.latest = BurpIO.getInstance().getLastestVersion(this.ID);
		this.outdated = false;
		
		if(this.latest == null)
			this.error = "Latest Version Not Found";
		else 
			this.compareVersions();
		
	}
	
	private void compareVersions(){		
		String versions[] = this.version.split("\\.");
		String latests[] = this.latest.split("\\.");
		
		for(int i = 0; i < versions.length; i++)			
			if(latests.length > i)
				try{					
					int v = Integer.parseInt(versions[i]);
					int l = Integer.parseInt(latests[i]);
										
					if(l > v){
						this.outdated = true;
						break;
					}
					
				} catch(NumberFormatException e){
					this.error = "Version Comparison Error - Wrong Version Numbers";
					break;
				}

	}
	
	public String getVersion(){
		return this.version;
	}
	
	public String getSoftware(){
		return this.software;
	}
	
	public String getLastesVersion(){
		return this.latest;
	}
	
	public boolean isOutOfDate(){
		return this.outdated;
	}
	
	public String errors(){
		return this.error;
	}

	public String[] getCves() {
		return BurpIO.getInstance().getCves(this.ID, this.version);
	}
}

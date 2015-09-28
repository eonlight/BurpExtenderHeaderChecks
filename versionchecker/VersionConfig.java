package versionchecker;

public class VersionConfig {
	
	public int id;
	public String url;
	public String regex;
	public String software;
	public String cves;

	public VersionConfig(String name, String url, String regex, String cves) {
		this.id = name.toLowerCase().hashCode();
		this.url = url;
		this.regex = regex;
		this.software = name;
		this.cves = cves;
	}
}

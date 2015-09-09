package versionchecker;

import java.util.List;
import java.util.regex.Matcher;
import java.util.ArrayList;
import java.util.Comparator;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import issues.InformationDisclosureIssue;
import issues.MissingHeadersIssue;
import issues.OutOfDateSoftwareIssue;
import issues.SecurityHeadersFoundIssue;

public class VersionChecker implements IScannerCheck {
	
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	
	private static final String NAME = "Version Checker";
	private static final String VERSION = "0.4.1";
	
	private static final String[] DEFAULT_SEARCH_HEADERS = new String[]{
			"Server", "X-Powered-By", "X-AspNetMvc-Version",
			"X-AspNet-Version", "X-Generator", "X-Drupal-Cache",
			"X-Pingback", "Liferay-Portal", "X-Content-Encoded-By"
	};
	
	private static final String[] DEFAULT_MISSING_HEADERS = new String[]{
			//"X-Frame-Options", 
			"Strict-Transport-Security", "X-XSS-Protection",
			"Content-Security-Policy", "X-Content-Type-Options", "X-Permitted-Cross-Domain-Policies"
	};
	
	public static String[] searchHeaders = DEFAULT_SEARCH_HEADERS.clone();
	public static String[] missingHeaders = DEFAULT_MISSING_HEADERS.clone();
	
	public static boolean additionalInfoIssue = false;
	
	public VersionChecker(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
		this.helpers = helpers;
		this.callbacks = callbacks;
		
		String additionalInfoSettings = callbacks.loadExtensionSetting("additionalInfoIssue");
		additionalInfoIssue = additionalInfoSettings != null && additionalInfoSettings.equals("true");
		
		String infoDisclosureCountSetting = callbacks.loadExtensionSetting("infoDisclosureCount");
		if(infoDisclosureCountSetting != null && !infoDisclosureCountSetting.equals("0")){
			searchHeaders = new String[Integer.parseInt(infoDisclosureCountSetting)];
			for(int i = 0; i < searchHeaders.length; i++)
				searchHeaders[i] = callbacks.loadExtensionSetting("infoDisclosure" + i);
		}
		
		String missingHeadersCountSetting = callbacks.loadExtensionSetting("missingHeadersCount");
		if(missingHeadersCountSetting != null && !missingHeadersCountSetting.equals("0")){
			missingHeaders = new String[Integer.parseInt(missingHeadersCountSetting)];
			for(int i = 0; i < missingHeaders.length; i++)
				missingHeaders[i] = callbacks.loadExtensionSetting("missingHeader" + i);
		}
		
		BurpIO.getInstance().write("[*] Loaded " + NAME + " v" + VERSION);
	}
	
	public static void saveCurrentInfoDisclosureHeaders(IBurpExtenderCallbacks callbacks){
		callbacks.saveExtensionSetting("infoDisclosureCount", "" + searchHeaders.length);
		
		for(int i = 0; i < searchHeaders.length; i++)
			callbacks.saveExtensionSetting("infoDisclosure" + i, searchHeaders[i]);
	}
	
	public static void saveCurrentMissingHeaders(IBurpExtenderCallbacks callbacks){
		callbacks.saveExtensionSetting("missingHeadersCount", "" + missingHeaders.length);
		
		for(int i = 0; i < missingHeaders.length; i++)
			callbacks.saveExtensionSetting("missingHeader" + i, missingHeaders[i]);
	}

	public static String[] getDefaultInfoDisclosureHeaders(){
		return DEFAULT_SEARCH_HEADERS.clone();
	}
	
	public static String[] getDefaultMissingHeaders(){
		return DEFAULT_MISSING_HEADERS.clone();
	}
	
	private String getHeaderMatch(byte[] response, byte[] match, List<int[]> matches){
		int limit = this.helpers.analyzeResponse(response).getBodyOffset();
		return getMatch(response, match, matches, limit);
	}
	
	private String getMatch(byte[] response, byte[] match, List<int[]> matches, int limit) {
		
		limit = limit < 0 ? response.length : limit;
        int start = this.helpers.indexOf(response, match, false, 0, limit);
        if (start != -1){
        	int end = this.helpers.indexOf(response, "\r\n".getBytes(), false, start, limit);
        	
        	matches.add(new int[]{start, end});
    		matches.sort(new Comparator<int[]>(){
				@Override
				public int compare(int[] o1, int[] o2) {
					if(o1[0] < o2[0] || (o1[0] == o2[0] && o1[1] < o2[1]))
						return -1; 
					else if(o1[0] > o2[0] || (o1[0] == o2[0] && o1[1] > o2[1]))
						return 1;
					return 0;
				}
			});
    		
        	return this.helpers.bytesToString(response).substring(start, end);
        }
        
        return null;
    }
	
	private List<OutOfDateSoftwareIssue> checkOutOfDateSoftware(IHttpRequestResponse requestResponse, List<String> headers){
		List<OutOfDateSoftwareIssue> issues = new ArrayList<OutOfDateSoftwareIssue>();
		
		for(String header : headers){
			
			boolean found = false;
			
			if(!header.contains(":"))
				continue;
			
			for(String value : header.split(":")[1].trim().split(" "))
				if(value.contains("/")){				
					String software = value.split("/")[0].trim();
					String version = value.split("/")[1].trim();
					VersionFinding vf = new VersionFinding(software, version);
	
					if(BurpExtender.DEBUG)
						BurpIO.getInstance().write("[-] " + vf.getSoftware() + ": " + vf.getVersion() + "/" + vf.getLastesVersion() + " - " + vf.isOutOfDate() + " | " + vf.errors());
					
					if(vf.isOutOfDate()){
						this.reportOODIssue(requestResponse, value, vf, issues);
						found = true;
					}
				}
					
			if(!found){
				String value = header.split(":")[1].trim();
				VersionFinding vf = searchVersion(value);				
				if(vf != null && vf.isOutOfDate())
					this.reportOODIssue(requestResponse, value, vf, issues);
			}
		}
		
		return issues;
	}
	
	private void reportOODIssue(IHttpRequestResponse requestResponse, String value, VersionFinding vf, List<OutOfDateSoftwareIssue> issues){
		OutOfDateSoftwareIssue oodIssue = new OutOfDateSoftwareIssue(this.helpers.analyzeRequest(requestResponse).getUrl());
		
		List<int[]> matches = new ArrayList<int[]>();
		this.getHeaderMatch(requestResponse.getResponse(), value.trim().getBytes(), matches);
		
		StringBuilder details = new StringBuilder();
		details.append("Base on the header <b>" + value.trim() + "</b> Version Checker determined that " + vf.getSoftware() + " is out-of-date: <br/>");
		details.append("<ul><li>Installed Version: <b>" + vf.getVersion() + "</b></li><li>Latest Version: <b>" + vf.getLastesVersion() + "</b></li></ul>");
		
		oodIssue.addRequestResponse(this.callbacks.applyMarkers(requestResponse, null, matches));
		oodIssue.setHttpService(requestResponse.getHttpService());
		oodIssue.setIssueDetail(details.toString());
		
		issues.add(oodIssue);
	}
	
	private VersionFinding searchVersion(String value) {		
		String version = null;
		Matcher matcher = VersionFinding.versionRegex.matcher(value);
		if(matcher.find())
			version = matcher.group(0);
		
		if(version != null){
			String software = value.split(" ")[0].trim();			
			return new VersionFinding(software, version);
		}
		
		return null;
	}

	private List<InformationDisclosureIssue> checkInformationDisclosure(IHttpRequestResponse requestResponse){
		
		InformationDisclosureIssue idIssue = new InformationDisclosureIssue(this.helpers.analyzeRequest(requestResponse).getUrl());
		StringBuilder details = new StringBuilder();
		List<int[]> matches = new ArrayList<int[]>();
		
		details.append("The response contains the header:<br/><ul>");
		for(String search : searchHeaders){
			String header = this.getHeaderMatch(requestResponse.getResponse(), search.getBytes(), matches);
			if(header != null){
				details.append("<li><b>" + header + "</b></li>");
				idIssue.headers.add(header);
			}
		}
		details.append("</ul>");
		

		if(idIssue.headers.size() > 0){

			idIssue.addRequestResponse(this.callbacks.applyMarkers(requestResponse, null, matches));
			idIssue.setHttpService(requestResponse.getHttpService());
			idIssue.setIssueDetail(details.toString());
			
			// Checks if issue already reported and if there are any new headers to report
			boolean report = false, found = false;
			String prefix = helpers.analyzeRequest(requestResponse).getUrl().getProtocol() + "://" + helpers.analyzeRequest(requestResponse).getUrl().getHost();
			IScanIssue[] reportedIssues = callbacks.getScanIssues(prefix);
			for(IScanIssue i : reportedIssues){
				if(i.getIssueName().equals(idIssue.getIssueName())){
					found = true;
					for(String h : idIssue.headers)
						if(!i.getIssueDetail().contains(h))
							report = true;
				}
			}
			
			if(report || !found){
				List<InformationDisclosureIssue> issues = new ArrayList<InformationDisclosureIssue>();
				issues.add(idIssue);
				return issues;
			}

		}
		
		return null;
	}
	
	private void reportMissingHeaderIssue(IHttpRequestResponse requestResponse, String missingHeader, List<IScanIssue> issues){
		MissingHeadersIssue mhIssue = new MissingHeadersIssue(this.helpers.analyzeRequest(requestResponse).getUrl());
		mhIssue.setHeader(missingHeader);
		
		StringBuilder details = new StringBuilder();
		details.append("The response does not contain the <b>" + missingHeader +  "</b> security headers:<br/>");
		mhIssue.setHttpService(requestResponse.getHttpService());
		mhIssue.setIssueDetail(details.toString());
			
		// Checks if issue already reported
		String prefix = helpers.analyzeRequest(requestResponse).getUrl().getProtocol() + "://" + helpers.analyzeRequest(requestResponse).getUrl().getHost();
		IScanIssue[] reportedIssues = callbacks.getScanIssues(prefix);
		for(IScanIssue i : reportedIssues)
			if(i.getIssueName().equals(mhIssue.getIssueName()))
				return;
		
		issues.add(mhIssue);
	}
	
	
	private List<IScanIssue> checkMissingHeaders(IHttpRequestResponse requestResponse) {
		SecurityHeadersFoundIssue hfIssue = new SecurityHeadersFoundIssue(this.helpers.analyzeRequest(requestResponse).getUrl());
		List<IScanIssue> issues = new ArrayList<IScanIssue>();

		
		StringBuilder hfDetails = new StringBuilder();
		List<int[]> matches = new ArrayList<int[]>();
		
		hfDetails.append("The following headers were found within the response headers:<br/><ul>");
		for(String search : missingHeaders){
			String header = this.getHeaderMatch(requestResponse.getResponse(), search.getBytes(), matches);
			if(header == null){
				reportMissingHeaderIssue(requestResponse, search, issues);
			} else if(additionalInfoIssue){
				hfDetails.append("<li><b>" + header + "</b></li>");
				hfIssue.headers.add(header);
			}
		}
		hfDetails.append("</ul>");
		

		if(hfIssue.headers.size() > 0){
			hfIssue.addRequestResponse(this.callbacks.applyMarkers(requestResponse, null, matches));
			hfIssue.setHttpService(requestResponse.getHttpService());
			hfIssue.setIssueDetail(hfDetails.toString());
			
			// Checks if issue already reported and if there are any new headers to report
			boolean report = false, found = false;
			String prefix = helpers.analyzeRequest(requestResponse).getUrl().getProtocol() + "://" + helpers.analyzeRequest(requestResponse).getUrl().getHost();
			IScanIssue[] reportedIssues = callbacks.getScanIssues(prefix);
			for(IScanIssue i : reportedIssues){
				if(i.getIssueName().equals(hfIssue.getIssueName())){
					found = true;
					for(String h : hfIssue.headers)
						if(!i.getIssueDetail().contains(h))
							report = true;
				}
			}
			
			if(report || !found)
				issues.add(hfIssue);
		}
		
		return issues;
	}
	
	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse requestResponse) {
		List<IScanIssue> issues = new ArrayList<IScanIssue>();
		List<InformationDisclosureIssue> idIssues = this.checkInformationDisclosure(requestResponse);

		if(idIssues != null && !idIssues.isEmpty()){
			for(InformationDisclosureIssue idIssue : idIssues){
				issues.add(idIssue);

				if(BurpExtender.DEBUG)
					BurpIO.getInstance().write("[+] Reporting: " + idIssue.getIssueName() + " for: " + idIssue.getHost());

				if(idIssue.headers.size() > 0){
					List<OutOfDateSoftwareIssue> oodIssues = this.checkOutOfDateSoftware(requestResponse, idIssue.headers);
					
					if(oodIssues != null && !oodIssues.isEmpty())
						for(OutOfDateSoftwareIssue oodIssue : oodIssues){
							issues.add(oodIssue);
							
							if(BurpExtender.DEBUG)
								BurpIO.getInstance().write("[+] Reporting: " + oodIssue.getIssueName() + " for: " + oodIssue.getHost());
						}
				}
				
			}
		}
		
		List<IScanIssue> mhIssues = this.checkMissingHeaders(requestResponse);
		if(mhIssues != null && !mhIssues.isEmpty()){
			for(IScanIssue mhIssue : mhIssues){
				issues.add(mhIssue);
				
				if(BurpExtender.DEBUG)
					BurpIO.getInstance().write("[+] Reporting: " + mhIssue.getIssueName() + " for: " + mhIssue.getHost());
			}
		}
		
		if(issues.isEmpty())
			return null;
		
		return issues;
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
		/*
		 * Server: Apache/2.4.12 (Unix) mod_wsgi/3.5 Python/2.7.5 OpenSSL/1.0.1l
		 * Server: Apache/2.2.22 (Debian)
		 * X-Powered-By: PHP/5.4.39-0+deb7u2
		 * Server: nginx/1.6.2
		 * X-Drupal-Cache: HIT
		 * X-Generator: Drupal 7 (http://drupal.org)
		 * X-Powered-By: PHP/5.3.29
		 * X-Content-Encoded-By: Joomla! 2.5
		 * X-Pingback: http://mexxer.pt/xmlrpc.php
		 * Check /wp-admin/wp-login.php
		 * Wordpress: /license.txt 
		 * Server: Apache-Coyote/1.1
		 * Set-Cookie: JSESSIONID=0567F682A7224B77DEB57A36FA7D3242
		 * Server: lighttpd/1.4.35
		 * Liferay-Portal: Liferay Portal Community Edition 6.2.0 CE GA1 (Newton / Build 6200 / November 1, 2013)
		 * Server: Apache/2.2.27 (Unix) mod_ssl/2.2.27 OpenSSL/1.0.1e-fips DAV/2 mod_bwlimited/1.4
		 * Server: Apache/2.2.4 (Unix) mod_perl/2.0.3 Perl/v5.8.8
		 * 178.236.159.72/tomcat-docs/index.html
		 */
		
		return null;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		if(BurpExtender.DEBUG)
			BurpIO.getInstance().write("Consolidating " + existingIssue.getIssueName() + " with " + newIssue.getIssueName());

		if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
			if(existingIssue.getIssueDetail().length() > newIssue.getIssueDetail().length())
				return -1;
			else if(existingIssue.getIssueDetail().length() < newIssue.getIssueDetail().length())
				return 1;
		return 0;
	}

}

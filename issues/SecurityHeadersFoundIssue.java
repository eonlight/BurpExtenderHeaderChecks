package issues;

import java.net.URL;
import java.util.ArrayList;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class SecurityHeadersFoundIssue extends ScanIssue {

	public ArrayList<String> headers;
	
	private static String DEFAULT_REMEDIATION = "This is just informational.";
	
	public SecurityHeadersFoundIssue(URL url){
		super("Security Headers Found", url, "Information", "Certain", "", DEFAULT_REMEDIATION, null, null);
		this.headers = new ArrayList<String>();
	}
	
	public SecurityHeadersFoundIssue(URL url, String severity, String confidence, String details, String remediation, IHttpRequestResponse[] requestsResponses, IHttpService service){
		super("Security Headers Found", url, severity, confidence, details, remediation, requestsResponses, service);
		this.headers = new ArrayList<String>();
	}

}

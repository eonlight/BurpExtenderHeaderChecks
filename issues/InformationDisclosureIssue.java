package issues;

import java.net.URL;
import java.util.ArrayList;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class InformationDisclosureIssue extends ScanIssue{
	
	public ArrayList<String> headers;
	
	private static String DEFAULT_REMEDIATION = "It is recommended that server's configurations be reviewed and information leackage through the response headers be removed.";

	public InformationDisclosureIssue(URL url){
		super("Information Disclosure Within Response Headers", url, "Medium", "Certain", "", DEFAULT_REMEDIATION, null, null);
		this.headers = new ArrayList<String>();
	}
	
	public InformationDisclosureIssue(URL url, String severity, String confidence, String details, String remediation, IHttpRequestResponse[] requestsResponses, IHttpService service){
		super("Information Disclosure Within Response Headers", url, severity, confidence, details, remediation, requestsResponses, service);
		this.headers = new ArrayList<String>();
	}

}
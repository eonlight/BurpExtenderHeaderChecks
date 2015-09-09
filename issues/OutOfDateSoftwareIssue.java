package issues;

import java.net.URL;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class OutOfDateSoftwareIssue extends ScanIssue {
	
	private static String DEFAULT_REMEDIATION = "It is recommended that all out-of-date software be updated to the latest version.";
	
	public OutOfDateSoftwareIssue(URL url){
		super("Out-Of-Date And Vulnerable Software Detected", url, "Medium", "Certain", "", DEFAULT_REMEDIATION, null, null);
	}
	
	public OutOfDateSoftwareIssue(URL url, String severity, String confidence, String details, String remediation, IHttpRequestResponse[] requestsResponses, IHttpService service){
		super("Out-Of-Date And Vulnerable Software Detected", url, severity, confidence, details, remediation, requestsResponses, service);
	}

}

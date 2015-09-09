package issues;

import java.net.URL;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class MissingHeadersIssue extends ScanIssue {
		
	private static String DEFAULT_REMEDIATION = "It is recommended that the reported missing header be added to the server response.";
	
	private String header = null;
	
	public MissingHeadersIssue(URL url){
		super("Missing Security Header", url, "Medium", "Certain", "", DEFAULT_REMEDIATION, null, null);
	}
	
	public MissingHeadersIssue(URL url, String severity, String confidence, String details, String remediation, IHttpRequestResponse[] requestsResponses, IHttpService service){
		super("Missing Security Header", url, severity, confidence, details, remediation, requestsResponses, service);
	}
	
	public void setHeader(String header){
		this.header = header;
		this.name = "Missing " + this.header + " Security Header";
	}

	public String getHeader(){
		return this.header;
	}
	
}

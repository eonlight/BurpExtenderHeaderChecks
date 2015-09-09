package issues;

import java.net.URL;
import java.util.ArrayList;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

public class ScanIssue implements IScanIssue {
	
	protected String name;
	
	private URL url;
	private String protocol;
	private String host;
	private int port;
	
	private String severity;
	private String confidence;
	private String details;
	private String remediation;

	private ArrayList<IHttpRequestResponse> burpRequestResponses;
	private IHttpService service;
	
	public ScanIssue(URL url){
		this("Abstract Scan Issue", url, "Medium", "Certain", "", "", null, null);
	}
	
	public ScanIssue(String name, URL url, String severity, String confidence, String details, String remediation, IHttpRequestResponse[] requestsResponses, IHttpService service){
		this(name, url, url.getProtocol(), url.getHost(), url.getPort(), severity, confidence, details, remediation, requestsResponses, service);
	}
	
	public ScanIssue(String name, URL url, String protocol, String host, int port, String severity, String confidence, String details, String remediation, IHttpRequestResponse[] requestsResponses, IHttpService service){
		this.name = name;
		this.url = url;
		
		this.protocol = protocol;
		this.host = host;
		this.port = port;

		this.severity = severity;
		this.confidence = confidence;
		
		this.details = details;
		this.remediation = remediation;
		
		this.burpRequestResponses = new ArrayList<IHttpRequestResponse>();
		if(requestsResponses != null)
			for(IHttpRequestResponse rr : requestsResponses)
				this.burpRequestResponses.add(rr);
		
		this.service = service;
	}

	@Override
	public URL getUrl() {
		return this.url;
	}
	
	public void setUrl(URL url){
		this.url = url;
	}
	
	@Override
	public String getIssueName() {
		return this.name;
	}

	@Override
	public int getIssueType() {
		return this.name.hashCode();
	}

	@Override
	public String getSeverity() {
		return this.severity;
	}
	
	public void setSeverity(String severity){
		this.severity = severity;
	}

	@Override
	public String getConfidence() {
		return this.confidence;
	}
	
	public void setCondifence(String confidence){
		this.confidence = confidence;
	}

	@Override
	public String getIssueBackground() {
		return null;
	}
	

	@Override
	public String getRemediationBackground() {
		return null;
	}

	@Override
	public String getIssueDetail() {
		return this.details;
	}
	
	public void setIssueDetail(String details){
		this.details = details;
	}

	@Override
	public String getRemediationDetail() {
		return this.remediation;
	}

	public void setRemediationDetail(String remediation){
		this.remediation = remediation;
	}
	
	@Override
	public IHttpRequestResponse[] getHttpMessages() {
		IHttpRequestResponse[] requestsResponses = new IHttpRequestResponse[this.burpRequestResponses.size()];
		for(int i = 0; i < this.burpRequestResponses.size(); i++)
			requestsResponses[i] = this.burpRequestResponses.get(i);
		return requestsResponses;
	}
	
	public void addRequestResponse(IHttpRequestResponse requestResponse) {
		this.burpRequestResponses.add(requestResponse);
	}

	@Override
	public IHttpService getHttpService() {
		return this.service;
	}
	
	public void setHttpService(IHttpService service){
		this.service = service;
	}

	@Override
	public String getHost() {
		return this.host;
	}
	
	public void setHost(String host) {
		this.host = host;
	}

	@Override
	public int getPort() {
		return this.port;
	}
	
	public void setPort(int port) {
		this.port = port;
	}


	@Override
	public String getProtocol() {
		return this.protocol;
	}
	
	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}


}
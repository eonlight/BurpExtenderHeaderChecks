package jsondecoder;

import java.awt.Component;
import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import burp.ITextEditor;
import versionchecker.BurpIO;

public class JsonDecoder implements IMessageEditorTabFactory {
	
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	
	private static final String NAME = "Json Decoder";
	private static final String VERSION = "1.0.0";
	
	public JsonDecoder(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
		BurpIO.getInstance().write("[*] Loaded " + NAME + " v" + VERSION);
		this.helpers = helpers;
		this.callbacks = callbacks;
	}
	
	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new JsonDecoderTab(controller, editable);
	}
	
	class JsonDecoderTab implements IMessageEditorTab{
		
		private static final String TAB_NAME = "JSON Decoder";
		
		private boolean editable;
		private ITextEditor textEditor;
		private byte[] message;
		
		public JsonDecoderTab(IMessageEditorController controller, boolean editable){
			this.editable = editable;
			this.message = null;
			
			this.textEditor = callbacks.createTextEditor();
			this.textEditor.setEditable(this.editable);
		}

		@Override
		public byte[] getMessage() {
			if(this.textEditor.isTextModified()){
				String data = helpers.bytesToString(this.textEditor.getText());
				
				try{
					data = new JSONObject(this.textEditor.getText()).toString(4);
				} catch(JSONException e){
					if(BurpExtender.DEBUG)
						e.printStackTrace(BurpIO.getInstance().stderr);
				}
				
				return helpers.buildHttpMessage(helpers.analyzeRequest(this.message).getHeaders(), helpers.stringToBytes(data));
			}
			
			return this.message;
		}

		@Override
		public byte[] getSelectedData() {
			return this.getSelectedData();
		}

		@Override
		public String getTabCaption() {
			return TAB_NAME;
		}

		@Override
		public Component getUiComponent() {
			return this.textEditor.getComponent();
		}
		
		private boolean checkHeaders(List<String> headers){
			for(String header : headers)
				if(header.startsWith("Content-Type:"))
					if(header.contains("application/json"))
						return true;

			return false;
		}

		@Override
		public boolean isEnabled(byte[] content, boolean isRequest) {
			List<String> headers = null;
			if(isRequest)
				headers = helpers.analyzeRequest(content).getHeaders();
			else
				headers = helpers.analyzeResponse(content).getHeaders();
				
			return checkHeaders(headers);
		}

		@Override
		public boolean isModified() {
			return this.textEditor.isTextModified();
		}

		@Override
		public void setMessage(byte[] content, boolean isRequest) {
			if(content == null || content.length == 0){
				this.textEditor.setText(content);
				this.textEditor.setEditable(isRequest);
			} else {
				int offset = -1;
				if(isRequest)
					offset = helpers.analyzeRequest(content).getBodyOffset();
				else
					offset = helpers.analyzeResponse(content).getBodyOffset();
				
				String body = helpers.bytesToString(content).substring(offset, content.length);

				try{
					this.textEditor.setText(helpers.stringToBytes(new JSONObject(body).toString(4)));
				} catch(JSONException e){
					if(BurpExtender.DEBUG)
						e.printStackTrace(BurpIO.getInstance().stderr);
					this.textEditor.setText(helpers.stringToBytes(body));
				}
				
				this.textEditor.setEditable(this.editable);
			}
			
			this.message = content;			
		}
		
	}

}

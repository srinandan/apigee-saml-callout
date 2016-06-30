package com.apigee.callout;

import java.io.StringWriter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.lang.text.StrSubstitutor;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.apigee.utils.TemplateString;

public class SAMLDecryptAssertion implements Execution {

	private Map<String,String> properties; // read-only
	 
	public SAMLDecryptAssertion(Map properties) {
	     // convert the untyped Map to a generic map
        Map<String,String> m = new HashMap<String,String>();
        Iterator iterator =  properties.keySet().iterator();
        while(iterator.hasNext()){
            Object key = iterator.next();
            Object value = properties.get(key);
            if ((key instanceof String) && (value instanceof String)) {
                m.put((String) key, (String) value);
            }
        }
        this.properties = m;		
	}
	
	private String getIssuer(MessageContext msgCtxt) throws Exception {
        String issuer = (String) this.properties.get("issuer");
        if (issuer == null || issuer.equals("")) {
            throw new IllegalStateException("issuer is not specified or is empty.");
        }
        issuer = resolvePropertyValue(issuer, msgCtxt);
        if (issuer == null || issuer.equals("")) {
            throw new IllegalStateException("issuer is not specified or is empty.");
        }
        return issuer;
    }
    
    private String[] getAudience(MessageContext msgCtxt) throws Exception {
        String audience = (String) this.properties.get("audience");
        if (audience == null || audience.equals("")) {
        	return null;
        }

        String[] audiences = StringUtils.split(audience,",");
        for(int i=0; i<audiences.length; i++) {
            audiences[i] = resolvePropertyValue(audiences[i], msgCtxt);
        }

        return audiences;
    }
    
    private String getPublicCert(MessageContext msgCtxt) throws Exception {
        String publicCert = (String) this.properties.get("publiccert");
        if (publicCert == null || publicCert.equals("")) {
            // don't care. 
            return null;
        }
        publicCert = resolvePropertyValue(publicCert, msgCtxt);
        if (publicCert == null || publicCert.equals("")) { return null; }
        return publicCert;    	
    }
    
    // If the value of a property value begins and ends with curlies,
    // eg, {apiproxy.name}, then "resolve" the value by de-referencing
    // the context variable whose name appears between the curlies.
    private String resolvePropertyValue(String spec, MessageContext msgCtxt) {
        if (spec.indexOf('{') > -1 && spec.indexOf('}')>-1) {
            // Replace ALL curly-braced items in the spec string with
            // the value of the corresponding context variable.
            TemplateString ts = new TemplateString(spec);
            Map<String,String> valuesMap = new HashMap<String,String>();
            for (String s : ts.variableNames) {
                valuesMap.put(s, (String) msgCtxt.getVariable(s));
            }
            StrSubstitutor sub = new StrSubstitutor(valuesMap);
            String resolvedString = sub.replace(ts.template);
            return resolvedString;
        }
        return spec;
    }
    
	@Override
	public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {

		try {
			String ISSUER = getIssuer(messageContext);
			String[] AUDIENCE = getAudience(messageContext);
			
			String encAssertion = messageContext.getMessage().getContent();
			//TODO: get the private key from the vault
			String privateKeyFile = "/resources/pkcs8.key";
			String publicKeyFile = "/resources/sei_public.pem";//using a default certificate
			
			SAML2Assertion saml = new SAML2Assertion();
			
			Assertion decryptedAssertion = saml.decrypt(encAssertion, privateKeyFile);
			//TODO:validate audience

			if (!saml.verifyAssertion(decryptedAssertion, publicKeyFile)) {
				throw new ValidationException("assertion is not valid!");
			}
			
			Map<String, String> samlAttributes = saml.getSAMLProperties(decryptedAssertion);
			
			if(!samlAttributes.get("Issuer").equalsIgnoreCase(ISSUER)) {
				throw new ValidationException("Invalid issuer in the Assertion/Response");
			}
			
			for (Map.Entry<String, String> entry : samlAttributes.entrySet()) {
				String key = entry.getKey();
				String providedValue = entry.getValue();
				messageContext.setVariable("saml_" + key, providedValue);
			}
			
			//store the decrypted assertion in the response
			Element plaintxt = saml.getPlainElement(decryptedAssertion);
			StringWriter writer = new StringWriter();
			TransformerFactory.newInstance().newTransformer().transform(new DOMSource(plaintxt), new StreamResult(writer));
			messageContext.setVariable("request.content", writer.toString());
			
			return ExecutionResult.SUCCESS;
		} catch (Throwable e) {
			e.printStackTrace();
			messageContext.setVariable("_error", e.getMessage());
			messageContext.setVariable("_stacktrace", ExceptionUtils.getStackTrace(e));
			return ExecutionResult.ABORT;
		}
	}
}

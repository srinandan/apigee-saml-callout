package com.apigee.callout;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.lang.text.StrSubstitutor;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.validation.ValidationException;

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
        	throw new IllegalStateException("audience is not specified or is empty.");
        }

        String[] audiences = StringUtils.split(audience,",");
        for(int i=0; i<audiences.length; i++) {
            audiences[i] = resolvePropertyValue(audiences[i], msgCtxt);
        }

        return audiences;
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
			String privateKeyFile = "/resources/pkcs8.key";
			String publicKeyFile = "/resources/public.pem";
			
			SAML2Assertion saml = new SAML2Assertion();
						
			Assertion decryptedAssertion = saml.decrypt(encAssertion, privateKeyFile);
			
			//TODO:validate issuer and audience
			
			if (!saml.verifyAssertion(decryptedAssertion, publicKeyFile)) {
				throw new ValidationException("signature not valid!");
			}
			
			Map<String, String> samlAttributes = saml.getSAMLProperties(decryptedAssertion);

			for (Map.Entry<String, String> entry : samlAttributes.entrySet()) {
				String key = entry.getKey();
				String providedValue = entry.getValue();
				messageContext.setVariable("saml_" + key, providedValue);
			}
			
			return ExecutionResult.SUCCESS;
		} catch (Throwable e) {
			e.printStackTrace();
			messageContext.setVariable("_error", e.getMessage());
			messageContext.setVariable("_stacktrace", ExceptionUtils.getStackTrace(e));
			return ExecutionResult.ABORT;
		}
	}

}

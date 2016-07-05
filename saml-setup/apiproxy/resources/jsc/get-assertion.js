 var response = context.getVariable("request.content");
 response = response.replace('SAMLResponse=','');
 response = urldecode(response);
 
 response = Base64.decode(response);
 
 context.setVariable("request.content", response);
 
 var clientid = properties.clientid;
 var clientsecret = properties.clientsecret;
 
 var baseStr = "Basic " + Base64.encode(clientid+":"+clientsecret);
 
 context.setVariable("basicAuth", baseStr);
 
 
 function urldecode(str) {
   return decodeURIComponent((str+'').replace(/\+/g, '%20'));
 }
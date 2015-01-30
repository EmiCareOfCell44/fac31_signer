
package me.run.face31;

import es.mityc.firmaJava.libreria.xades.AllXMLToSign;
import es.mityc.firmaJava.libreria.xades.FirmaXML;
import es.mityc.firmaJava.libreria.xades.elementos.xades.DataToSign;
import es.mityc.javasign.EnumFormatoFirma;
import es.mityc.javasign.XAdESSchemas;
import es.mityc.javasign.pkstore.mscapi.MSCAPIStore;
import es.mityc.javasign.pkstore2.CertStoreException;
import es.mityc.javasign.pkstore2.IPKStoreManager;
import es.mityc.javasign.xml.refs.ObjectToSign;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import es.mityc.firmaJava.libreria.xades2.X509KeySelector;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 *
 * @author Emiliano Martinez
 */

class Signature
{
   protected Document getDocument(String resource) {
        Document doc = null;
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        try {
        	doc = (Document) dbf.newDocumentBuilder().parse(resource);
        } catch (ParserConfigurationException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        } catch (SAXException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        } catch (IOException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        } catch (IllegalArgumentException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        }
        return doc;
    }


    protected DataToSign createDataToSign(String inputDoc) {
        DataToSign dataToSign = new DataToSign();
        dataToSign.setXadesFormat(EnumFormatoFirma.XAdES_BES);
        dataToSign.setEsquema(XAdESSchemas.XAdES_132);
        dataToSign.setXMLEncoding("UTF-8");
        dataToSign.setEnveloped(true);

        dataToSign.setPolicyKey("facturae30");
        dataToSign.setAddPolicy(true);

        Document docToSign = getDocument(inputDoc);
        try{
        dataToSign.setDocument((org.w3c.dom.Document) docToSign);
        dataToSign.addObject(new es.mityc.firmaJava.libreria.xades.ObjectToSign(new AllXMLToSign(), "", null, "text/xml", null));
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return dataToSign;
    }
}

public class Main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {

        FirmaXML sign = new FirmaXML();
        X509Certificate cert = null;
        IPKStoreManager sm = null;
        DataToSign data = new DataToSign();
        KeyStore ks = null;
        Signature _signature = new Signature();
        
        System.out.println("\n\n\n\n\n\n\n\n\n\n\n");
        
        System.out.println(" \t\t\t\t>>>>>>>>>------------------------------");
        System.out.println(" \t\t\t\t        ------");
        System.out.println(" \t\t\t\t       /");
        System.out.println(" \t\t\t\t      /---");
        System.out.println(" \t\t\t\t     /          ------               ");
        System.out.println(" \t\t\t\t    /    --    /--                   ");
        System.out.println(" \t\t\t\t   /          /___                   ");
        System.out.println(" \t\t\t\t------------------------------<<<<<<<<<");
        
        System.out.println("\n\n\n\n\n\n\n\n\n\n\n\n");
        
        System.out.println("\t\t\t\tPRESS 1 to Sign \n");
        System.out.println("\t\t\t\tPRESS 2 to Validate \n");
        
        System.out.println("\n\n\n\n\n\n\n\n\n\n\n\n");
        
        InputStreamReader input = new InputStreamReader(System.in);
		BufferedReader br = new BufferedReader (input);
		
		try { 
		     
			 String choice = br.readLine();	
			
		     if(choice.equals("1"))
		     {
		        System.out.println("Input file to sign: ");
                String file = br.readLine();	
        
                /** File to be signed **/
                DataToSign dataToSign = _signature.createDataToSign(file);
                Security.addProvider(new BouncyCastleProvider());
        
                try {
          
        	    /** ks = KeyStore.getInstance("Windows-MY");  -- CAPI -- **/            
        	    /** ks.load(null, null); **/            
        	
        	    System.out.println("Input P12 keystore: ");        	
        	    String keystore = br.readLine();
        	
        	    System.out.println("Input JKS keystore password: ");
        	    String _password = br.readLine(); 
        	
        	    ks = KeyStore.getInstance("PKCS12","BC");
        	    ks.load(new FileInputStream(keystore), _password.toCharArray());        	
        	
                List<X509Certificate> certs = es.mityc.javasign.pkstore.KeyTool.getCertificatesWithKeys(ks);            
            
                /** Only one cert with associated private key **/
                cert = certs.get(0);
            
                /** Get alias with openssl info **/
                System.out.println("Input Alias: ");
                String _alias = br.readLine();
              
                PrivateKey resultado = (PrivateKey) ks.getKey(_alias, _password.toCharArray());

                /** File to stored signed invoice **/
                System.out.println("File to store signed order: ");
                String _storeFile = br.readLine(); 
                File __file = new File(_storeFile);
                FileOutputStream _stream = new FileOutputStream(__file);

                sign.signFile(cert, dataToSign, resultado, _stream, ks.getProvider());
        
              } catch (Exception ex) {
                  Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
              }
		    }
	    	else if(choice.equals("2")){
				
			   System.out.println("Validating...");
			   System.out.println("Input file to validate: ");
	           String _fileSigned = br.readLine();
	        	
			   DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			   factory.setNamespaceAware(true);
				
			   DocumentBuilder builder = factory.newDocumentBuilder();
			   Document doc = builder.parse(_fileSigned);
				
			   NodeList nl = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");
			   if (nl.getLength() == 0) {
				 throw new Exception("Cannot find Signature element");
			   }
				
			   X509KeySelector keySelector = new X509KeySelector();
			   DOMValidateContext valContext = new DOMValidateContext(keySelector, nl.item(0));									
			   XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
				
			   javax.xml.crypto.dsig.XMLSignature signature = fac.unmarshalXMLSignature(valContext);
				
			   /** Validating xml dsig **/
			   boolean coreValidity = signature.validate(valContext);					
			   System.out.println("Signature valid " + coreValidity);	
		}
					
		}catch(Exception e){e.printStackTrace();}
		
    }

}

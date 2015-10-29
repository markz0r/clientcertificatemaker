package KeyStore;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 *
 * @author Mark Culhane, 2014
 */
public class KeyStoreController {  
    
    private static KeyPair keyPair;
    private static String keyPassword;
    private static Certificate certificate;
    private static String keyName;
    private static String outputDir;
     /*    
     * Key Constructor with no arg
     * 
     */
    public KeyStoreController(int bitLength, String keyPassword, String inKeyName, String inOutputDir) {
        try {
            //ASSUMES ALL NEW - new keypair and new CSR
            keyName = inKeyName;
            outputDir = inOutputDir;
            KeyStoreController.keyPair = new KeyPair(bitLength, keyPassword, keyName, outputDir);
            KeyStoreController.keyPassword = keyPassword;
        } catch (FileNotFoundException ex) {
            Logger.getLogger(KeyStoreController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(KeyStoreController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*    
     * Key Constructor with filePath arg
     * 
     */
    public KeyStoreController(String keyPassword, String keyPath, String keyName) throws FileNotFoundException, IOException {
            // opens existing keypair assuming filename 'myKeyPair.pem' and path provided
        KeyStoreController.keyPair = new KeyPair(keyPassword, keyPath, keyName);
        KeyStoreController.keyPassword = keyPassword;
    }

    public void setCert(String certAbsPath) {
            KeyStoreController.certificate = new Certificate(certAbsPath, keyPair, keyPassword);
    }
    

    //http://stackoverflow.com/questions/9711173/convert-ssl-pem-to-p12-with-or-without-openssl
    public void exportPKCS12(String outputAbsPath) {      
        certificate.writePKCS12(outputAbsPath);
    }
        
    public String getCSR(String x500Text) {
        String csrVal = null;
        try {       
            csrVal = keyPair.getCSR(x500Text, keyName, outputDir);
        } catch (IOException ex) {
            Logger.getLogger(KeyStoreController.class.getName()).log(Level.SEVERE, null, ex);
        }
        return csrVal;
    }
    
    public String getPrivate() {
        return keyPair.getPrivateKey().toString();
    }
    
   
}
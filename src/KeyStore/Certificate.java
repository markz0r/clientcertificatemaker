package KeyStore;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

/**
 *
 * @author Mark Culhane
 */
public class Certificate {
    private static X509Certificate x509Cert; 
    private static KeyPair keyPair;
    private static String keyPassword;
    /*
     * Default contructor
     * @ param String certPath specified cert to add
     */
    public Certificate(String certAbsPath, KeyPair existingKeyPair, String keyPassword) {
        PEMParser pemParser = null;
        try {
            keyPair = existingKeyPair;
            Certificate.keyPassword = keyPassword;
            File certFile = new File(certAbsPath);
            pemParser = new PEMParser(new FileReader(certFile));
            Object pemObject = pemParser.readObject();
            System.out.println(pemObject.toString());
            if (pemObject instanceof X509CertificateHolder) {
                X509CertificateHolder tmpHolder = (X509CertificateHolder)pemObject;
                x509Cert = new JcaX509CertificateConverter().getCertificate(tmpHolder);
                x509Cert.checkValidity(); // to check it's valid in time
                System.out.println("signed cert is time valid");
                //x509Cert.verify(existingKeyPair.getPublicKey()); // verify the sig. using the issuer's public key
                //System.out.println("signed cert has a valid sig??");
            } else{
                System.out.println(certFile + " was not successfully parsed as a pem X509Certificate");
            }
                
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Certificate.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateExpiredException ex) {
            Logger.getLogger(Certificate.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateNotYetValidException ex) {
            Logger.getLogger(Certificate.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(Certificate.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Certificate.class.getName()).log(Level.SEVERE, null, ex);
        }  finally {
            try {
                pemParser.close();
            } catch (IOException ex) {
                Logger.getLogger(Certificate.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    
    public void writePKCS12(String outputAbsPath) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            //ks.setKeyEntry("myKey", keyPair.getPrivateKey(), keyPassword.toCharArray(), new java.security.cert.Certificate[]{x509Cert});
            ks.setKeyEntry("myKey", keyPair.getPrivateKey(), 
                    keyPassword.toCharArray(), 
                    new java.security.cert.Certificate[]{x509Cert});
            
            System.out.println(outputAbsPath);
            FileOutputStream fOut = new FileOutputStream(outputAbsPath);
            ks.store(fOut, keyPassword.toCharArray());
        } catch (KeyStoreException ex) {
            Logger.getLogger(Certificate.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Certificate.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Certificate.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(Certificate.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}

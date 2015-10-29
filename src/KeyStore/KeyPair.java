package KeyStore;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;

/**
 *
 * @author Mark Culhane
 */
public class KeyPair {
   private java.security.KeyPair keyPair;
   private CSR csr;
    
    /*
     * Default constructor
     * @param bitLenght default is 2048 from package controller
     * @param password is input by user, default is 'abc123'
     */
    public KeyPair(Integer bitLength, String inPassword, String keyName, String outputDir) throws FileNotFoundException, IOException {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(bitLength);
            keyPair = gen.generateKeyPair();                    
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(KeyPair.class.getName()).log(Level.SEVERE, null, ex);
        }
        writeKeyPair(inPassword, keyName, outputDir, keyPair);
        //writeKeyPair(filePath + "myPrivate.pem", keyPair.getPrivate());
        //writeKeyPair(filePath + "myPublic.pem", keyPair.getPublic());
    }
    
        /*
     * Existing Key Constructor
     * @param inPassword is input by user, default is 'abc123'
     * @param inFilePath refers to path of keypair
     */
    public KeyPair(String keyPassword, String keyPath, String keyName) throws FileNotFoundException, IOException {
        File privateKeyFile = new File(keyPath + File.separatorChar + keyName);
        PEMParser pemParser = new PEMParser(new FileReader(privateKeyFile));
        Object object = pemParser.readObject();
        PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(keyPassword.toCharArray());
        //JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        if (object instanceof PEMEncryptedKeyPair) {
            System.out.println("Encrypted key - we will use provided password");
            keyPair = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
        } else {
            System.out.println("Unencrypted key - no password needed");
            keyPair = converter.getKeyPair((PEMKeyPair) object);
        }
    }
    
    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }
    
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }
    
    public String getCSR(String x500Text, String csrName, String outputDir) throws IOException {
        csr =  new CSR(keyPair, x500Text, csrName, outputDir);
        return csr.getCSR(csrName, outputDir);
    }
    
    private void writeKeyPair(String keyPassword, String keyName, String outputDir, Object pemObject) throws FileNotFoundException, IOException {
        File file = new File(outputDir + File.separatorChar + keyName + ".key.pem");
        JcePEMEncryptorBuilder encBuild = new JcePEMEncryptorBuilder("DES-EDE3-CBC");
        PEMEncryptor myEncryptor = encBuild.build(keyPassword.toCharArray());
        
        try (FileOutputStream fop = new FileOutputStream(file)) {
            file.createNewFile();
            OutputStreamWriter output = new OutputStreamWriter(fop);
            try (PEMWriter pem = new PEMWriter(output)) {
                pem.writeObject(pemObject, myEncryptor);
            }
        }
    }
}
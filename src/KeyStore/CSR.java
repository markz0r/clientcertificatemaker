package KeyStore;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 *
 * @author Mark Culhane
 */
public class CSR {
    
    private static X500Principal subject;
    private static ContentSigner signGen;
    private static PKCS10CertificationRequest csr;
    private static String csrExtension = ".csr.pem";

    
    public CSR(java.security.KeyPair keyPair, String x500Text, String csrName, String outputDir) throws FileNotFoundException, IOException {
        try {
            subject = new X500Principal (x500Text);
            signGen = new JcaContentSignerBuilder("SHA1withRSA").build(keyPair.getPrivate());

            //create CSR
            PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
            csr = builder.build(signGen);

        } catch (OperatorCreationException ex) {
            Logger.getLogger(CSR.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        //write CSR to file
            writeCSR(csrName, outputDir);
    }
          
    private void writeCSR(String csrName, String outputDir) throws FileNotFoundException, IOException {
        File file = new File(outputDir + File.separatorChar + csrName + csrExtension);
        try (FileOutputStream fop = new FileOutputStream(file)) {
            file.createNewFile();
            OutputStreamWriter output = new OutputStreamWriter(fop);
            try (PEMWriter pem = new PEMWriter(output)) {
                pem.writeObject(csr);
            }
        }
    }
    // 
    public String getCSR(String keyName, String outputDir) throws FileNotFoundException, IOException {
        BufferedReader reader = new BufferedReader(new FileReader (outputDir + File.separatorChar + keyName + csrExtension));
        String line = null;
        StringBuilder stringBuilder = new StringBuilder();
        String ls = System.getProperty("line.separator");

        while( ( line = reader.readLine() ) != null ) {
            stringBuilder.append( line );
            stringBuilder.append( ls );
        }

        return stringBuilder.toString();
    }    
}

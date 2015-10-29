import KeyStoreGUI.MainFrame;
import javax.swing.JFrame;

/**
 *
 * @author Mark Culhane, 2014
 */

// Example: http://www.simsudo.com/generating-csr-using-java-and-bouncycastle-api.html
public class PackageController {
 
    public static void main(String[] args) {
        JFrame mainMenuFrame = new MainFrame();
        mainMenuFrame.setTitle("Simple Client SSL tool");
        mainMenuFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        mainMenuFrame.setVisible(true);
    }   
}

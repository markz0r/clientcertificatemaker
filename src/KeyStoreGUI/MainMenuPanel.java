/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package KeyStoreGUI;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.Box;
import javax.swing.DefaultListModel;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.ListModel;

/**
 *
 * @author lp1
 */
public class MainMenuPanel extends javax.swing.JPanel {
    private static Integer bitLength = 2048;
    private static String outputDir = "output";
    private DefaultListModel filesInDirectory = new DefaultListModel();
    
    /**
     * Creates new form KeyPanel
     */
    public MainMenuPanel() {
        initComponents();
        //Insert code for including a list of pemkeys
        File folder = new File(outputDir);
        
        fileListField.setModel((ListModel) listFilesForDir(folder));
    }
    
    //Populate list
    private DefaultListModel listFilesForDir( final File folder) {
            Integer i = 0;
            for (final File fileEntry : folder.listFiles()) {
                System.out.println(fileEntry.getName());
                if (fileEntry.isDirectory()) {  
                    listFilesForDir(fileEntry);
                } else {
                        if(fileEntry.getName().toUpperCase().endsWith(".KEY.PEM")){
                            filesInDirectory.add(i,fileEntry.getName());
                            i++;
                        }
                       }
        }
    return filesInDirectory;
    }
    
    private static String getPassword(String message) {
        JPasswordField jpf = new JPasswordField(24);
        JLabel jl = new JLabel(message);
        Box box = Box.createHorizontalBox();
        box.add(jl);
        box.add(jpf);
        // TODO get password input field to pull focus
        int x = JOptionPane.showConfirmDialog(null, box, "Password Entry", JOptionPane.OK_CANCEL_OPTION);
        
        if (x == JOptionPane.OK_OPTION) {
        //TODO dont store passswords as string, use char[]
        return  new String (jpf.getPassword());
    }
    return null;
  }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        generateNewButton = new javax.swing.JButton();
        openExistingButton = new javax.swing.JToggleButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        csrTextField = new javax.swing.JTextArea();
        jSeparator1 = new javax.swing.JSeparator();
        jScrollPane3 = new javax.swing.JScrollPane();
        fileListField = new javax.swing.JList();

        setMinimumSize(new java.awt.Dimension(1023, 305));
        setPreferredSize(new java.awt.Dimension(1024, 305));

        generateNewButton.setText("Generate new key and CSR");
        generateNewButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                generateNewButtonActionPerformed(evt);
            }
        });

        openExistingButton.setText("Combine selected key with certificate");
        openExistingButton.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                openExistingButtonMouseReleased(evt);
            }
        });
        openExistingButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                openExistingButtonActionPerformed(evt);
            }
        });

        csrTextField.setEditable(false);
        csrTextField.setColumns(20);
        csrTextField.setFont(new java.awt.Font("Courier New", 0, 12)); // NOI18N
        csrTextField.setRows(5);
        csrTextField.setAutoscrolls(false);
        csrTextField.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                csrTextFieldMouseClicked(evt);
            }
        });
        jScrollPane1.setViewportView(csrTextField);

        jSeparator1.setOrientation(javax.swing.SwingConstants.VERTICAL);

        fileListField.setModel(new javax.swing.AbstractListModel() {
            String[] strings = { "Item 1", "Item 2", "Item 3", "Item 4", "Item 5" };
            public int getSize() { return strings.length; }
            public Object getElementAt(int i) { return strings[i]; }
        });
        fileListField.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                fileListFieldMouseReleased(evt);
            }
        });
        jScrollPane3.setViewportView(fileListField);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap(13, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 470, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(generateNewButton, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 470, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(openExistingButton, javax.swing.GroupLayout.DEFAULT_SIZE, 470, Short.MAX_VALUE)
                    .addComponent(jScrollPane3))
                .addGap(29, 29, 29))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 273, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(generateNewButton)
                            .addComponent(openExistingButton))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 243, Short.MAX_VALUE)
                            .addComponent(jScrollPane3))))
                .addContainerGap(14, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void generateNewButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_generateNewButtonActionPerformed
        String keyPassword = getPassword("Enter new key password: ");
        String keyPassword2 = getPassword("Confirm password: ");
        if (keyPassword.equals(keyPassword2)) {
            String c = JOptionPane.showInputDialog(null, "Enter country code (http://www.digicert.com/ssl-certificate-country-codes.htm for valid options): ","", 1);
            String o = JOptionPane.showInputDialog(null, "Organisation name: ","", 1);
            String cn = JOptionPane.showInputDialog(null, "Common name: ","", 1);
            String email = JOptionPane.showInputDialog(null, "Contact email: ","", 1);
            String x500Text = "C=" + c + ", O=" + o + ", CN=" + cn + ", EMAILADDRESS=" + email;
            KeyStore.KeyStoreController newKeySess = new KeyStore.KeyStoreController(bitLength, keyPassword, cn, outputDir);
            csrTextField.setVisible(true);
            csrTextField.setText(newKeySess.getCSR(x500Text));
        } else
             JOptionPane.showMessageDialog(null, "Passwords do not match", "Oops", JOptionPane.INFORMATION_MESSAGE);
    }//GEN-LAST:event_generateNewButtonActionPerformed

    private void csrTextFieldMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_csrTextFieldMouseClicked
        csrTextField.selectAll();
    }//GEN-LAST:event_csrTextFieldMouseClicked

    private void openExistingButtonMouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_openExistingButtonMouseReleased
        KeyStore.KeyStoreController openKeySess = null;
        String certAbsolutePath = null;
        String exportAbsPath = null;
        try {
            String keyPassword = getPassword("Enter new key password: ");
            openKeySess = new KeyStore.KeyStoreController(keyPassword, outputDir, fileListField.getSelectedValue().toString());
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MainMenuPanel.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MainMenuPanel.class.getName()).log(Level.SEVERE, null, ex);
        }
        //Enter/Select certificate
        JOptionPane.showMessageDialog(null, "Please select the BT signed certificate", "Select cert", JOptionPane.INFORMATION_MESSAGE);
        JFileChooser chooser = new JFileChooser();
        int returnVal, returnVal2;
        chooser.setCurrentDirectory(new File(outputDir));
        returnVal = chooser.showOpenDialog(this);
        if(returnVal == JFileChooser.APPROVE_OPTION) {
            certAbsolutePath = chooser.getSelectedFile().getAbsolutePath();          
        }
        JOptionPane.showMessageDialog(null, "Please define p12 output path and filename", "Select p12 output", JOptionPane.INFORMATION_MESSAGE);
        openKeySess.setCert(certAbsolutePath);
        returnVal2 = chooser.showSaveDialog(this);
        if(returnVal2 == JFileChooser.APPROVE_OPTION) {
            exportAbsPath = chooser.getSelectedFile().getAbsolutePath();
        }
        
        openKeySess.exportPKCS12(exportAbsPath);
        JOptionPane.showMessageDialog(null, "PKCS12 certificate writen to " + exportAbsPath +
                "/n Double click on file to install");
    }//GEN-LAST:event_openExistingButtonMouseReleased

    private void openExistingButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_openExistingButtonActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_openExistingButtonActionPerformed

    private void fileListFieldMouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_fileListFieldMouseReleased
        
        
    }//GEN-LAST:event_fileListFieldMouseReleased

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea csrTextField;
    private javax.swing.JList fileListField;
    private javax.swing.JButton generateNewButton;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JToggleButton openExistingButton;
    // End of variables declaration//GEN-END:variables
}

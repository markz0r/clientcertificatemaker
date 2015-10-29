/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package KeyStoreGUI;

import javax.swing.JFileChooser;

/**
 *
 * @author lp1
 */
public class CertificatePanel extends javax.swing.JPanel {

    /**
     * Creates new form Certificate
     */
    public CertificatePanel() {
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        textCertificateField = new javax.swing.JTextArea();
        jLabel1 = new javax.swing.JLabel();
        chooseCertFromFile = new javax.swing.JButton();
        createCertFile = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JSeparator();

        textCertificateField.setColumns(20);
        textCertificateField.setRows(5);
        jScrollPane1.setViewportView(textCertificateField);

        jLabel1.setText("Enter certificate text:");

        chooseCertFromFile.setText("Choose certificate from file");
        chooseCertFromFile.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                chooseCertFromFileMouseReleased(evt);
            }
        });
        chooseCertFromFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chooseCertFromFileActionPerformed(evt);
            }
        });

        createCertFile.setText("Generate brower certificate");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jSeparator1, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 553, Short.MAX_VALUE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(chooseCertFromFile)
                            .addComponent(createCertFile, javax.swing.GroupLayout.PREFERRED_SIZE, 218, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(chooseCertFromFile)
                .addGap(7, 7, 7)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 5, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 189, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(createCertFile)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void chooseCertFromFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chooseCertFromFileActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_chooseCertFromFileActionPerformed

    private void chooseCertFromFileMouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_chooseCertFromFileMouseReleased
        // open file selector dialogue
        JFileChooser chooser = new JFileChooser();
        //FileNameExtensionFilter filter = new FileNameExtensionFilter(
        //"JPG & GIF Images", "jpg", "gif");
        //chooser.setFileFilter(filter);
        int returnVal;
        returnVal = chooser.showOpenDialog(this);
        if(returnVal == JFileChooser.APPROVE_OPTION) {
            certAbsolutePath = chooser.getSelectedFile().getAbsolutePath();
            System.out.println("You chose to open this file: " +
            certAbsolutePath);
            
        }
           
        this.setVisible(false);
    }//GEN-LAST:event_chooseCertFromFileMouseReleased

    public String getCertPath() {
        return certAbsolutePath;
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton chooseCertFromFile;
    private javax.swing.JButton createCertFile;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JTextArea textCertificateField;
    // End of variables declaration//GEN-END:variables
    private String certAbsolutePath;
}

package des;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.Base64;

public class DES {

    public static void main(String[] args) throws Exception {
        // Get DES key
        byte[] keyBytes = "mydeskey".getBytes();
        DESKeySpec desKeySpec = new DESKeySpec(keyBytes);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(desKeySpec);

        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        while (true) {
            // Choose operation
            String[] options = {"Encrypt", "Decrypt"};
            int choice = JOptionPane.showOptionDialog(null, "Choose operation:", "DES Encryption/Decryption", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, options, options[0]);

            if (choice == 0) { // Encrypt
                String plaintext = JOptionPane.showInputDialog("Enter the message to encrypt:");
                if (plaintext != null && !plaintext.isEmpty()) {
                    byte[] plaintextBytes = plaintext.getBytes();

                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    byte[] encryptedBytes = cipher.doFinal(plaintextBytes);
                    String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);

                    JPanel panel = new JPanel(new GridLayout(0, 1));
                    panel.add(new JLabel("Encrypted message:"));
                    JTextField textField = new JTextField(encryptedMessage);
                    panel.add(textField);
                    JButton copyButton = new JButton("Copy to Clipboard");
                    copyButton.addActionListener(e -> {
                        try {
                            StringSelection stringSelection = new StringSelection(encryptedMessage);
                            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                            clipboard.setContents(stringSelection, null);
                            JOptionPane.showMessageDialog(null, "Encrypted message copied to clipboard.");
                        } catch (Exception ex) {
                            ex.printStackTrace();
                            JOptionPane.showMessageDialog(null, "Error copying to clipboard.", "Error", JOptionPane.ERROR_MESSAGE);
                        }
                    });
                    panel.add(copyButton);
                    JOptionPane.showMessageDialog(null, panel, "Encrypted Message", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(null, "Invalid input!", "Error", JOptionPane.ERROR_MESSAGE);
                }
            } else if (choice == 1) { // Decrypt
                String encryptedMessage = JOptionPane.showInputDialog("Enter the message to decrypt:");
                if (encryptedMessage != null && !encryptedMessage.isEmpty()) {
                    cipher.init(Cipher.DECRYPT_MODE, secretKey);
                    byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
                    String decryptedMessage = new String(decryptedBytes);

                    JOptionPane.showMessageDialog(null, "Decrypted message:\n" + decryptedMessage);
                } else {
                    JOptionPane.showMessageDialog(null, "Invalid input!", "Error", JOptionPane.ERROR_MESSAGE);
                }
            } else {
                JOptionPane.showMessageDialog(null, "Invalid choice!", "Error", JOptionPane.ERROR_MESSAGE);
            }

            // Ask user if they want to decrypt again
            int option = JOptionPane.showConfirmDialog(null, "Do you want to perform another decryption?", "Decrypt Again?", JOptionPane.YES_NO_OPTION);
            if (option != JOptionPane.YES_OPTION) {
                break;
            }
        }
    }
}

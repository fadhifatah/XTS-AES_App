import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.concurrent.TimeUnit;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

public class GUIMain extends JFrame {

	public static JFileChooser fc = new JFileChooser();
	public static JFrame frame = new JFrame("XTS-AES");
	public static JPanel menuPanel;

	public static File input1;
	public static File input2;
	public static File output;
	public static boolean isSetOutput = false;

	public static void procedurePanel(int flag) {
		
		frame.setTitle("XTS-AES " + ((flag == 1) ? "Encryption" : "Decryption"));

		// Initiate panel, label, and constraint
		JLabel inputLabel1 = new JLabel(String.format("%1$-20s %2$2s", ((flag == 1) ? "Plaintext" : "Ciphertext"), ""));
		JPanel filePanel = new JPanel(new GridBagLayout());
		GridBagConstraints constraints = new GridBagConstraints();
		constraints.anchor = GridBagConstraints.WEST;
		constraints.insets = new Insets(10, 10, 10, 10);

		// Initiate text field for input 1
		JTextField inputLocation1 = new JTextField(20);
		inputLocation1.setEditable(false);
		inputLocation1.setBorder(BorderFactory.createCompoundBorder(
				inputLocation1.getBorder(),
				BorderFactory.createEmptyBorder(5, 5, 5, 5)));
		
		// Initiate text field for input 2
		JTextField inputLocation2 = new JTextField(20);
		inputLocation2.setEditable(false);
		inputLocation2.setBorder(BorderFactory.createCompoundBorder(
				inputLocation2.getBorder(),
				BorderFactory.createEmptyBorder(5, 5, 5, 5)));

		// Initiate text field for output
		JTextField outputLocation = new JTextField(20);
		outputLocation.setEditable(false);
		outputLocation.setBorder(BorderFactory.createCompoundBorder(
				outputLocation.getBorder(),
				BorderFactory.createEmptyBorder(5, 5, 5, 5)));

		// Initiate button for input 1
		JButton inputButton1 = new JButton("Browse...");
		ActionListener action;
		action = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				int returnValue = fc.showOpenDialog(null);
				if (returnValue == JFileChooser.APPROVE_OPTION) {
					File selectedFile = fc.getSelectedFile();
					input1 = selectedFile;
					inputLocation1.setText(input1.getAbsolutePath());
					if (!isSetOutput) {
						String[] temp = input1.getAbsolutePath().split("\\.");
						outputLocation.setText(temp[0] + ((flag == 1) ? "_encrypted." : "_decrypted.") + temp[1]);
					}
				}
			}
		};

		// Add component into panel
		inputButton1.addActionListener(action);
		inputButton1.setPreferredSize(new Dimension(90, 30));
		constraints.gridx = 0;
		constraints.gridy = 0;
		filePanel.add(inputLabel1, constraints);
		constraints.gridx = 1;
		filePanel.add(inputLocation1, constraints);
		constraints.gridx = 2;
		filePanel.add(inputButton1, constraints);

//		fileLabel = new JLabel("Input Key :");
		JLabel inputLabel2 = new JLabel(String.format("%1$-20s %2$2s", "Key", ""));

		// Initiate button for input 2
		JButton inputButton2 = new JButton("Browse...");
		action = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				int returnValue = fc.showOpenDialog(null);
				if (returnValue == JFileChooser.APPROVE_OPTION) {
					File selectedFile = fc.getSelectedFile();
					input2 = selectedFile;
					inputLocation2.setText(input2.getAbsolutePath());
				}
			}
		};
		
		// Add component into panel
		inputButton2.addActionListener(action);
		inputButton2.setPreferredSize(new Dimension(90, 30));
		constraints.gridx = 0;
		constraints.gridy = 1;
		filePanel.add(inputLabel2, constraints);
		constraints.gridx = 1;
		filePanel.add(inputLocation2, constraints);
		constraints.gridx = 2;
		filePanel.add(inputButton2, constraints);

		JLabel outputLabel = new JLabel(String.format("%1$-20s %2$2s", ((flag == 1) ? "Ciphertext (output)" : "Plaintext (output)"), ""));

		// Initiate button for output
		JButton outputButton = new JButton("Browse...");
		action = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				int returnValue = fc.showSaveDialog(null);
				if (returnValue == JFileChooser.APPROVE_OPTION) {
					File selectedFile = fc.getSelectedFile();
					output = selectedFile;
					outputLocation.setText(output.getAbsolutePath());
					isSetOutput = true;
				}
			}
		};
		
		// Add component into panel
		outputButton.addActionListener(action);
		outputButton.setPreferredSize(new Dimension(90, 30));
		constraints.gridx = 0;
		constraints.gridy = 2;
		filePanel.add(outputLabel, constraints);
		constraints.gridx = 1;
		filePanel.add(outputLocation, constraints);
		constraints.gridx = 2;
		filePanel.add(outputButton, constraints);

		// Initiate button for back
		JButton backButton = new JButton("Back");
		action = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				frame.setSize(300, 300);
				frame.setLocationRelativeTo(null);
				frame.setContentPane(menuPanel);
				frame.invalidate();
				frame.validate();
			}
		};
		
		// Add component into panel
		backButton.addActionListener(action);
		backButton.setPreferredSize(new Dimension(90, 30));
		constraints.gridx = 0;
		constraints.gridy = 3;
		filePanel.add(backButton, constraints);

		// Initiate button for proceed
		JButton proceedButton = new JButton((flag == 1) ? "Encrypt" : "Decrypt");
		action = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				try {
					// Proceed XTS-AES Simulation here

					// String result = Main.readFile(input1, input2);
					// FileWriter writer = new FileWriter(output);
					// writer.write(result);
					// writer.close();
					// System.out.println("Complete");
//					showProcess();
//					TimeUnit.SECONDS.sleep(5);
					boolean success = Main.readFile(input1, input2);
					resultPanel(success, flag);
//					if (success) {
//						System.out.println("Completed");
//					}
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		};
		
		// Add component into panel
		proceedButton.addActionListener(action);
		proceedButton.setPreferredSize(new Dimension(90, 30));
		constraints.gridx = 2;
		constraints.gridy = 3;
		filePanel.add(proceedButton, constraints);

		// Set frame panel
		frame.setSize(600, 300);
		frame.setLocationRelativeTo(null);
		frame.setContentPane(filePanel);
		frame.invalidate();
		frame.validate();
	}
	
	public static void resultPanel(boolean success, int flag) {
		String status = "";
		String detail = "";
		
		if (flag == 1) {
			status = "Encryption ";
			detail = "The encrypted ";
		} else {
			status = "Decryption ";
			detail = "The decrypted ";
		}
		
		if (success) {
			status += "completed !";
			detail += "file successfully created.";
		} else {
			status += "failed !";
			detail += "file failed to be created.";
		}
		JLabel statusLabel = new JLabel(status);
		statusLabel.setFont(new Font("Arial", Font.BOLD, 20));
		JLabel detailLabel = new JLabel(detail);
		JPanel statusPanel = new JPanel(new GridBagLayout());
		GridBagConstraints constraints = new GridBagConstraints();
		constraints.anchor = GridBagConstraints.WEST;
		constraints.insets = new Insets(10, 10, 10, 10);

		constraints.gridx = 0;
		constraints.gridy = 0;
		statusPanel.add(statusLabel, constraints);

		constraints.gridx = 0;
		constraints.gridy = 1;
		statusPanel.add(detailLabel, constraints);
		
		JButton menuButton = new JButton("Menu");
		ActionListener action = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				frame.setSize(300, 300);
				frame.setLocationRelativeTo(null);
				frame.setContentPane(menuPanel);
				frame.invalidate();
				frame.validate();
			}
		};
		
		// Add component into panel
		menuButton.addActionListener(action);
		menuButton.setPreferredSize(new Dimension(90, 30));
		constraints.gridx = 0;
		constraints.gridy = 2;
		constraints.anchor = GridBagConstraints.CENTER;
		statusPanel.add(menuButton, constraints);
		
		frame.setSize(300, 300);
		frame.setLocationRelativeTo(null);
		frame.setContentPane(statusPanel);
		frame.invalidate();
		frame.validate();
	}
	
	public static void showProcess() {
		JLabel loading = new JLabel("Processing...");
		loading.setFont(new Font("Arial", Font.BOLD, 20));
		JPanel processPanel = new JPanel(new GridBagLayout());
		GridBagConstraints constraints = new GridBagConstraints();
		constraints.anchor = GridBagConstraints.WEST;
		constraints.insets = new Insets(10, 10, 10, 10);
		
		constraints.gridx = 0;
		constraints.gridy = 0;
		constraints.anchor = GridBagConstraints.CENTER;
		processPanel.add(loading, constraints);
		
		frame.setSize(300, 300);
		frame.setLocationRelativeTo(null);
		frame.setContentPane(processPanel);
		frame.invalidate();
		frame.validate();
	}

	public static void main(String[] args) {

		menuPanel = new JPanel(new GridBagLayout());
		GridBagConstraints constraints = new GridBagConstraints();
		constraints.anchor = GridBagConstraints.WEST;
		constraints.insets = new Insets(10, 10, 10, 10);

//		JLabel title = new JLabel("<html>File Encryption & Decryption using XTS-AES mode with 256 bits key. Choose what you want to do with your file :</html>");
//		constraints.gridx = 0;
//		constraints.gridy = 0;
//		menuPanel.add(title, constraints);
		
		JButton menuButton = new JButton("Encryption");
		ActionListener action = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				procedurePanel(1);
			}
		};
		menuButton.addActionListener(action);
		menuButton.setPreferredSize(new Dimension(100, 30));

		constraints.gridx = 0;
		constraints.gridy = 1;
		menuPanel.add(menuButton, constraints);

		menuButton = new JButton("Decryption");
		action = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				procedurePanel(2);
			}
		};
		menuButton.addActionListener(action);
		menuButton.setPreferredSize(new Dimension(100, 30));

		constraints.gridx = 0;
		constraints.gridy = 2;
		menuPanel.add(menuButton, constraints);

		JButton exitButton = new JButton("E X I T");
		action = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				System.exit(0);
			}
		};
		exitButton.addActionListener(action);
		exitButton.setPreferredSize(new Dimension(100, 30));

		constraints.gridx = 0;
		constraints.gridy = 3;
//		constraints.gridwidth = 2;
//		constraints.anchor = GridBagConstraints.CENTER;
		menuPanel.add(exitButton, constraints);

		frame.add(menuPanel);
		frame.setSize(300, 300);
		frame.setLocationRelativeTo(null);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setVisible(true);
	}

}
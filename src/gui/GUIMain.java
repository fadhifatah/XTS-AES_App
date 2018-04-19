package gui;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

public class GUIMain extends JFrame {
	
	public static JFileChooser fc = new JFileChooser();
	public static JFrame frame = new JFrame("XTS-AES Encryption & Decryption");

	public static File input1;
	public static File input2;
	public static File output;

	public static void procedurePanel(int flag) {
		frame.setTitle("XTS-AES " + ((flag == 1) ? "Encryption" : "Decryption"));

		JLabel fileLabel = new JLabel((flag == 1) ? "Input Plaintext :" : "Input Ciphertext :");
		JPanel filePanel = new JPanel();
		filePanel.setLayout(new GridLayout(4,2,10,10));
		filePanel.setBorder(new EmptyBorder(20, 20, 20, 20));

		JButton inputButton1 = new JButton("Browse...");
		ActionListener action;
		action = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				int returnValue = fc.showOpenDialog(null);
				if (returnValue == JFileChooser.APPROVE_OPTION) {
					File selectedFile = fc.getSelectedFile();
					input1 = selectedFile;
					String[] temp = selectedFile.getAbsolutePath().split("\\\\");
					inputButton1.setText(temp[temp.length-1]);
				}
			}
		};
		inputButton1.addActionListener(action);
		filePanel.add(fileLabel);
		filePanel.add(inputButton1);
		
		fileLabel = new JLabel("Input Key :");
		JButton inputButton2 = new JButton("Browse...");
		action = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				int returnValue = fc.showOpenDialog(null);
				if (returnValue == JFileChooser.APPROVE_OPTION) {
					File selectedFile = fc.getSelectedFile();
					input2 = selectedFile;
					String[] temp = selectedFile.getAbsolutePath().split("\\\\");
					inputButton2.setText(temp[temp.length-1]);
				}
			}
		};
		inputButton2.addActionListener(action);
		filePanel.add(fileLabel);
		filePanel.add(inputButton2);

		fileLabel = new JLabel((flag == 1) ? "Output Ciphertext :" : "Output Plaintext :");
		JButton outputButton = new JButton("Browse...");
		action = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				int returnValue = fc.showSaveDialog(null);
				if (returnValue == JFileChooser.APPROVE_OPTION) {
					File selectedFile = fc.getSelectedFile();
					output = selectedFile;
					String[] temp = selectedFile.getAbsolutePath().split("\\\\");
					outputButton.setText(temp[temp.length-1]);
				}
			}
		};
		outputButton.addActionListener(action);
		filePanel.add(fileLabel);
		filePanel.add(outputButton);
		
		JButton proceedButton = new JButton("Proceed");
		action = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				try {
					// Proceed XTS-AES Simulation here
					
//					String result = Main.readFile(input1, input2);
//					FileWriter writer = new FileWriter(output);
//					writer.write(result);
//					writer.close();
//					System.out.println("Complete");
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		};
		proceedButton.addActionListener(action);
		filePanel.add(proceedButton);
		
		frame.setContentPane(filePanel);
		frame.invalidate();
		frame.validate();
	}
	
	public static void main(String[] args) {

		JPanel menuPanel = new JPanel();
		menuPanel.setLayout(new GridLayout(2,2,10,10));

		JButton menuButton = new JButton("Encryption");
		ActionListener action = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				procedurePanel(1);
			}
		};
		menuButton.addActionListener(action);
		menuPanel.add(menuButton);
		
		menuButton = new JButton("Decryption");
		action = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				procedurePanel(2);
			}
		};
		menuButton.addActionListener(action);
		menuPanel.add(menuButton);

		frame.add(menuPanel);
		frame.setSize(300, 300);
		frame.setLocationRelativeTo(null);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setVisible(true);
	}
	
}
import java.awt.EventQueue;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JPanel;

public class GUIMain extends JFrame {
	
	JFileChooser fc = new JFileChooser();
	BufferedReader fileReader;
	File inputPlaintext;
	File inputKey;
	File outputPlaintext;

	public GUIMain(String title) {
		super(title);
		setDefaultCloseOperation(EXIT_ON_CLOSE);

		JPanel pnl = new JPanel();
		pnl.setLayout(new GridLayout(5, 3));

		JButton btn = new JButton("Input Plaintext");
		ActionListener al;
		al = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				int returnValue = fc.showOpenDialog(null);
				if (returnValue == JFileChooser.APPROVE_OPTION) {
					File selectedFile = fc.getSelectedFile();
					inputPlaintext = selectedFile;
					try {
						fileReader = new BufferedReader(new FileReader(inputPlaintext));
						String line = "";
						while ((line = fileReader.readLine()) != null) {
							System.out.println(line);
						}
					} catch (Exception e) {
						e.printStackTrace();
					}
					System.out.println(selectedFile.getAbsolutePath());
				}
			}
		};
		btn.addActionListener(al);
		pnl.add(btn);
		
		btn = new JButton("Input Key");
		al = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				int returnValue = fc.showOpenDialog(null);
				if (returnValue == JFileChooser.APPROVE_OPTION) {
					File selectedFile = fc.getSelectedFile();
					inputKey = selectedFile;
					System.out.println(selectedFile.getAbsolutePath());
				}
			}
		};
		btn.addActionListener(al);
		pnl.add(btn);

		btn = new JButton("Output");
		al = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				int returnValue = fc.showSaveDialog(null);
				if (returnValue == JFileChooser.APPROVE_OPTION) {
					File selectedFile = fc.getSelectedFile();
					outputPlaintext = selectedFile;
					System.out.println(selectedFile.getAbsolutePath());
				}
			}
		};
		btn.addActionListener(al);
		pnl.add(btn);

		setContentPane(pnl);

		pack();
		setVisible(true);
	}

	public static void main(String[] args) {
		Runnable r = new Runnable() {
			@Override
			public void run() {
				new GUIMain("XTS-AES");
			}
		};
		EventQueue.invokeLater(r);
	}
}
package ModifyRequestSignature;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

import java.awt.*;

import java.util.ArrayList;

import utils.SignatureUtils;

public class ModifyRequestSignature implements BurpExtension
{
    public static boolean modificationEnabled;
    public final ArrayList<String> displayedAlgorithm = new ArrayList<>();
    public static ArrayList<String> algorithm = new ArrayList<>();
    public static String header;
    public static String field;
    public static String secret;
    public static JToggleButton includeNonInterceptedRequestsButton = new JToggleButton("Include non-intercepted proxied requests");

    @Override
    public void initialize(MontoyaApi api)
    {
        modificationEnabled = false;
        api.extension().setName("Modify Request Signature");
        api.userInterface().registerSuiteTab("Modify Request Signature", constructTab());
        api.http().registerHttpHandler(new MyHttpHandler(api));
    }

    private JScrollPane constructTab() {
        // ----------------------------------- User Interface -----------------------------------
        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout());
        panel.setBorder(new EmptyBorder(5, 5, 5, 5));

        // Wrap the entire panel in a JScrollPane
        JScrollPane mainScrollPane = new JScrollPane(panel);
        mainScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        mainScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);


        // Top panel with JTextFields and buttons
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new GridLayout(1, 2));
        topPanel.setBorder(new EmptyBorder(100, 300, 0, 300));


        // Left side of the top panel (JTextFields with JLabels)
        JPanel leftTopPanel = new JPanel();
        leftTopPanel.setLayout(new BoxLayout(leftTopPanel, BoxLayout.Y_AXIS)); // Vertical layout for labels above fields
        leftTopPanel.setBorder(new EmptyBorder(0, 0, 0, 5));
        // Header field
        JLabel headerLabel = new JLabel("Header");
        JTextField headerField = new JTextField(20);
        leftTopPanel.add(headerLabel);
        leftTopPanel.add(headerField);
        leftTopPanel.add(Box.createVerticalStrut(10)); // Add spacing between fields

        // Hash field
        JLabel hashLabel = new JLabel("Hash Field");
        JTextField hashField = new JTextField(20);
        leftTopPanel.add(hashLabel);
        leftTopPanel.add(hashField);
        leftTopPanel.add(Box.createVerticalStrut(10)); // Add spacing between fields

        // Secret field
        JLabel secretLabel = new JLabel("Secret");
        JTextField secretField = new JTextField(20);
        leftTopPanel.add(secretLabel);
        leftTopPanel.add(secretField);
        leftTopPanel.add(Box.createVerticalStrut(10)); // Add spacing between fields

        // Right side of the top panel (Scrollable Buttons for algorithms)
        JPanel rightTopPanel = new JPanel();
        rightTopPanel.setLayout(new BorderLayout());
        rightTopPanel.setBorder(new EmptyBorder(0, 5, 0, 0));

        // Create a panel for the buttons and add them
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new FlowLayout(FlowLayout.LEFT)); // Horizontal flow for buttons

        JButton base64UrlButton = new JButton("Base64URL");
        JButton base64Button = new JButton("Base64");
        JButton sha256Button = new JButton("SHA256");

        buttonPanel.add(base64UrlButton);
        buttonPanel.add(base64Button);
        buttonPanel.add(sha256Button);

        // Change only the height while letting the width be dynamic
        Dimension preferredSize = buttonPanel.getPreferredSize();
        preferredSize.height = 40; // Set the height you want
        buttonPanel.setPreferredSize(preferredSize);

        // Make the button panel scrollable
        JScrollPane buttonScrollPane = new JScrollPane(buttonPanel);
        buttonScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        buttonScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER); // Only horizontal scrolling

        rightTopPanel.add(buttonScrollPane, BorderLayout.NORTH);

        // Non-editable text area for Algorithm with label
        JPanel algorithmPanel = new JPanel();
        algorithmPanel.setLayout(new BorderLayout());

        JLabel algorithmLabel = new JLabel("Algorithm", JLabel.CENTER); // Center the label
        JTextField algorithmField = new JTextField("RequestBody"); // Create a JTextField instead of JTextArea
        algorithmField.setEditable(false); // Make it non-editable
        JButton clearButton = new JButton("Clear Algorithm");

        algorithmPanel.add(algorithmLabel, BorderLayout.NORTH);
        algorithmPanel.add(algorithmField, BorderLayout.CENTER);
        algorithmPanel.add(clearButton, BorderLayout.SOUTH);

        rightTopPanel.add(algorithmPanel, BorderLayout.CENTER);

        topPanel.add(leftTopPanel);
        topPanel.add(rightTopPanel);

        panel.add(topPanel, BorderLayout.NORTH);

        // Middle panel with two buttons
        JPanel middleButtonPanel = new JPanel();
        middleButtonPanel.setLayout(new FlowLayout(FlowLayout.CENTER));
        middleButtonPanel.setBorder(new EmptyBorder(5, 0, 0, 0));

        JButton testButton = new JButton("Test");
        JButton saveSettingsButton = new JButton("Save settings");
        JButton clearSettingsButton = new JButton("Stop modifying");
        JLabel settingsLabel = new JLabel("Not currently modifying edited requests");
        
        middleButtonPanel.add(testButton);
        middleButtonPanel.add(saveSettingsButton);
        middleButtonPanel.add(includeNonInterceptedRequestsButton);
        middleButtonPanel.add(clearSettingsButton);
        middleButtonPanel.add(settingsLabel);

        panel.add(middleButtonPanel, BorderLayout.CENTER);

        // Bottom panel with two text areas
        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new GridLayout(5, 1));
        bottomPanel.setBorder(new EmptyBorder(0, 300, 100, 300));

        // Top text area for Old Signature
        JPanel oldSignaturePanel = new JPanel();
        oldSignaturePanel.setLayout(new BorderLayout());

        JLabel oldSignatureLabel = new JLabel("Old Signature");
        JTextArea oldSignatureArea = new JTextArea(4,30);
        oldSignatureArea.setEditable(true); // Make it non-editable
        oldSignatureArea.setLineWrap(true);
        oldSignatureArea.setWrapStyleWord(true);

        JScrollPane oldSignatureScrollPane = new JScrollPane(oldSignatureArea);
        oldSignatureScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        oldSignatureScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        oldSignaturePanel.add(oldSignatureLabel, BorderLayout.NORTH);
        oldSignaturePanel.add(oldSignatureScrollPane, BorderLayout.CENTER);

        // Top text area for Request Body
        JPanel requestBodyPanel = new JPanel();
        requestBodyPanel.setLayout(new BorderLayout());

        JLabel newRequestBodyLabel = new JLabel("New Request Body");
        JTextArea newRequestBodyArea = new JTextArea(4, 30);
        newRequestBodyArea.setEditable(true); // Make it non-editable
        newRequestBodyArea.setLineWrap(true);
        newRequestBodyArea.setWrapStyleWord(true);

        JScrollPane requestBodyScrollPane = new JScrollPane(newRequestBodyArea);
        requestBodyScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        requestBodyScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        requestBodyPanel.add(newRequestBodyLabel, BorderLayout.NORTH);
        requestBodyPanel.add(requestBodyScrollPane, BorderLayout.CENTER);

        // Bottom text area for Signature
        JPanel hashPanel = new JPanel();
        hashPanel.setLayout(new BorderLayout());

        JLabel newHashLabel = new JLabel("New Hash");
        JTextArea newHashField = new JTextArea(4, 30);
        newHashField.setEditable(false); // Make it non-editable

        JScrollPane hashPane = new JScrollPane(newHashField);
        hashPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        hashPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED); // Only horizontal scrolling
        hashPanel.add(newHashLabel, BorderLayout.NORTH);
        hashPanel.add(hashPane, BorderLayout.CENTER);

        // Bottom text area for Signature
        JPanel newSignaturePanel = new JPanel();
        newSignaturePanel.setLayout(new BorderLayout());

        JLabel newSignatureLabel = new JLabel("New Signature");
        JTextArea newSignatureArea = new JTextArea(4, 30);
        newSignatureArea.setEditable(false); // Make it non-editable
        newSignatureArea.setLineWrap(true);
        newSignatureArea.setWrapStyleWord(true);

        JScrollPane newSignatureScrollPane = new JScrollPane(newSignatureArea);
        newSignatureScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        newSignatureScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        newSignaturePanel.add(newSignatureLabel, BorderLayout.NORTH);
        newSignaturePanel.add(newSignatureScrollPane, BorderLayout.CENTER);

        JLabel errorLabel = new JLabel();
        errorLabel.setForeground(Color.RED);

        bottomPanel.add(errorLabel);
        bottomPanel.add(oldSignaturePanel);
        bottomPanel.add(requestBodyPanel);
        bottomPanel.add(hashPanel);
        bottomPanel.add(newSignaturePanel);

        panel.add(bottomPanel, BorderLayout.SOUTH);

        // ----------------------------------- EVENT LISTENERS -----------------------------------

        clearButton.addActionListener(e -> {
            displayedAlgorithm.clear();
            algorithmField.setText("RequestBody");
        });

        base64Button.addActionListener(e -> {
            displayedAlgorithm.add("Base64");
            algorithmField.setText("Base64( " + algorithmField.getText() + " )");
        });

        base64UrlButton.addActionListener(e -> {
            displayedAlgorithm.add("Base64URL");
            algorithmField.setText("Base64URL( " + algorithmField.getText() + " )");
        });

        sha256Button.addActionListener(e -> {
            displayedAlgorithm.add("SHA256");
            algorithmField.setText("SHA256( " + algorithmField.getText() + " )");
        });

        testButton.addActionListener(e -> {
            if (hashField.getText().isEmpty() || secretField.getText().isEmpty() || newRequestBodyArea.getText().isEmpty() || oldSignatureArea.getText().isEmpty()) {
                errorLabel.setText("Error: Please fill in Hash Field, New Request Body, and Old Signature to test.");
            } else if (!displayedAlgorithm.isEmpty() && displayedAlgorithm.getLast().startsWith("SHA")) {
                errorLabel.setText("Error: Raw SHA digest must be encoded");
            } else {
                try {
                    ArrayList testData = SignatureUtils.calculateNewSignature(displayedAlgorithm, hashField.getText(), secretField.getText(), newRequestBodyArea.getText(), oldSignatureArea.getText());
                    newSignatureArea.setText((String) testData.getFirst());
                    newHashField.setText((String) testData.getLast());
                    errorLabel.setText("");
                } catch (Exception ex) {
                    errorLabel.setText(ex.getMessage());
                }
            }
        });

        saveSettingsButton.addActionListener(e -> {
            if (headerField.getText().isEmpty() || hashField.getText().isEmpty() || secretField.getText().isEmpty()) {
                errorLabel.setText("Error: Please fill in header and claim field of hashed body to save.");
            } else if (!displayedAlgorithm.isEmpty() && displayedAlgorithm.getLast().startsWith("SHA")) {
                errorLabel.setText("Error: Raw SHA digest must be encoded");
            } else {
                errorLabel.setText("");
                try {
                    algorithm = displayedAlgorithm;
                    modificationEnabled = true;
                    header = headerField.getText();
                    field = hashField.getText();
                    secret = secretField.getText();

                    settingsLabel.setText("Currently modifying header \""+header+"\"");
                } catch (Exception ex) {
                    errorLabel.setText(ex.getMessage());
                }
            }
        });

        includeNonInterceptedRequestsButton.addActionListener(e -> {

        });

        clearSettingsButton.addActionListener(e -> {
            modificationEnabled = false;
            settingsLabel.setText("Not currently modifying edited requests");
        });

        return mainScrollPane;
    }
}
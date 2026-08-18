package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

public class ZeroXMatrixTab extends JPanel {

    private final MontoyaApi api;
    private final JTable table;
    private final DefaultTableModel tableModel;
    private final JLabel statusLabel;

    // Parsed request/response messages corresponding to each table row
    private final List<HttpRequestResponse> displayedMessages = new CopyOnWriteArrayList<>();
    private final List<HighlightColor> displayedColors = new CopyOnWriteArrayList<>();

    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    public ZeroXMatrixTab(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;

        // Top Control Panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton clearButton = new JButton("Clear Results");
        clearButton.addActionListener(e -> clearResults());
        controlPanel.add(clearButton);

        JButton aboutButton = new JButton("About");
        aboutButton.addActionListener(e -> showAbout());
        controlPanel.add(aboutButton);

        statusLabel = new JLabel("Status: Ready");
        controlPanel.add(statusLabel);

        add(controlPanel, BorderLayout.NORTH);

        // Table Model with 7 columns
        String[] columnNames = {"Timestamp", "Method", "URL", "Role (Color)", "Status Code", "Response Length", "Similarity %"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Read-only
            }
        };

        table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);

        // Custom Cell Renderer for the "Role (Color)" column (Index 3)
        // Displays a colored dot next to the Role Name
        table.getColumnModel().getColumn(3).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                int modelRow = table.convertRowIndexToModel(row);
                if (modelRow >= 0 && modelRow < displayedColors.size()) {
                    HighlightColor color = displayedColors.get(modelRow);
                    setIcon(new ColorDotIcon(color));
                } else {
                    setIcon(null);
                }
                return this;
            }
        });

        // Custom Cell Renderer for the "Status Code" column (Index 4)
        // Color-codes the HTTP Status Codes for better readability in screenshots
        table.getColumnModel().getColumn(4).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                setHorizontalAlignment(javax.swing.SwingConstants.CENTER);

                if (value instanceof Integer) {
                    int statusCode = (Integer) value;
                    if (isSelected) {
                        // Keep selection background but color the text nicely
                        if (statusCode >= 200 && statusCode < 300) {
                            setForeground(new java.awt.Color(74, 222, 128)); // Bright Green
                        } else if (statusCode >= 300 && statusCode < 400) {
                            setForeground(new java.awt.Color(253, 186, 116)); // Bright Orange
                        } else if (statusCode >= 400 && statusCode < 500) {
                            setForeground(new java.awt.Color(248, 113, 113)); // Bright Red
                        } else if (statusCode >= 500) {
                            setForeground(new java.awt.Color(239, 68, 68)); // Crimson Red
                        } else {
                            setForeground(table.getSelectionForeground());
                        }
                    } else {
                        // Apply soft, professional pastel colors based on status code range
                        if (statusCode >= 200 && statusCode < 300) {
                            setBackground(new java.awt.Color(220, 252, 231)); // Soft Green
                            setForeground(new java.awt.Color(21, 128, 61));    // Dark Green
                        } else if (statusCode >= 300 && statusCode < 400) {
                            setBackground(new java.awt.Color(254, 243, 199)); // Soft Yellow
                            setForeground(new java.awt.Color(180, 83, 9));     // Dark Yellow/Orange
                        } else if (statusCode >= 400 && statusCode < 500) {
                            setBackground(new java.awt.Color(254, 226, 226)); // Soft Red
                            setForeground(new java.awt.Color(185, 28, 28));    // Dark Red
                        } else if (statusCode >= 500) {
                            setBackground(new java.awt.Color(252, 165, 165)); // Stronger Soft Red
                            setForeground(new java.awt.Color(153, 27, 27));    // Very Dark Red
                        } else {
                            setBackground(table.getBackground());
                            setForeground(table.getForeground());
                        }
                    }
                } else {
                    if (!isSelected) {
                        setBackground(table.getBackground());
                        setForeground(table.getForeground());
                    }
                }
                return this;
            }
        });

        JScrollPane tableScrollPane = new JScrollPane(table);

        // Create Request / Response editors (Read-Only)
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        // Horizontal split pane for Request and Response editors
        JSplitPane editorsSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestEditor.uiComponent(), responseEditor.uiComponent());
        editorsSplitPane.setResizeWeight(0.5); // 50/50 split
        editorsSplitPane.setDividerLocation(0.5);

        // Vertical split pane: Table on top, Request/Response on bottom
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, editorsSplitPane);
        mainSplitPane.setResizeWeight(0.4); // 40% height to table, 60% to editors
        mainSplitPane.setDividerLocation(250);

        add(mainSplitPane, BorderLayout.CENTER);

        // List Selection Listener to show details when a row is clicked
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = table.getSelectedRow();
                if (viewRow >= 0) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    if (modelRow >= 0 && modelRow < displayedMessages.size()) {
                        HttpRequestResponse msg = displayedMessages.get(modelRow);
                        if (msg != null) {
                            requestEditor.setRequest(msg.request());
                            if (msg.response() != null) {
                                responseEditor.setResponse(msg.response());
                            } else {
                                responseEditor.setResponse(null);
                            }
                        }
                    }
                }
            }
        });
    }

    public void setStatus(String status) {
        statusLabel.setText("Status: " + status);
    }

    public void addResult(HttpRequestResponse reqRes, String method, String url, HighlightColor color, String roleName, int statusCode, int length, int similarity) {
        String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());
        String colorName = color.name().toLowerCase();
        String roleText = roleName + " (" + colorName + ")";

        // Sync table and list updates on EDT
        javax.swing.SwingUtilities.invokeLater(() -> {
            displayedMessages.add(reqRes);
            displayedColors.add(color);
            tableModel.addRow(new Object[]{
                timestamp,
                method,
                url,
                roleText,
                statusCode,
                length,
                similarity + "%"
            });
        });
    }

    private void clearResults() {
        int confirm = JOptionPane.showConfirmDialog(
            this,
            "Are you sure you want to clear all matrix results?",
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION
        );
        if (confirm == JOptionPane.YES_OPTION) {
            tableModel.setRowCount(0);
            displayedMessages.clear();
            displayedColors.clear();
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
            setStatus("Ready (Cleared)");
        }
    }

    private void showAbout() {
        JOptionPane.showMessageDialog(
            this,
            "ZeroX Burp Suite Extension v2.0.0\n" +
            "Advanced Session Bridge & Privilege Escalation Analyzer\n\n" +
            "Powered by PortSwigger Montoya API.\n" +
            "Author: @anonre",
            "About ZeroX",
            JOptionPane.INFORMATION_MESSAGE
        );
    }
}

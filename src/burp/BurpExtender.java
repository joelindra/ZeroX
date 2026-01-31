package burp;

import java.awt.*;
import java.awt.event.*;
import java.awt.geom.RoundRectangle2D;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;

public class BurpExtender implements IBurpExtender, IProxyListener, IExtensionStateListener, IHttpListener, IContextMenuFactory, ITab {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    // Store request history with their colors
    private Map<String, List<IHttpRequestResponse>> requestHistoryByColor;
    
    // Store Authorization headers per color with timestamp
    private Map<String, String> authHeadersByColor;
    private Map<String, Long> authHeaderTimestamps;
    
    // Max age for auth headers (1 hour in milliseconds)
    private static final long MAX_AUTH_AGE_MS = 60 * 60 * 1000;
    
    // Available colors matching Firefox extension container colors
    private static final String[] COLORS = {
        "red", "orange", "yellow", "green", "cyan", "blue", "purple", "pink"
    };
    
    // ==================== White/Light Theme Colors ====================
    private static final Color BG_PRIMARY = new Color(255, 255, 255);   // #ffffff - White
    private static final Color BG_SECONDARY = new Color(248, 250, 252); // #f8fafc - Light Gray
    private static final Color BG_ELEVATED = new Color(241, 245, 249);  // #f1f5f9 - Slightly darker
    private static final Color BG_CARD = new Color(255, 255, 255);      // #ffffff - White
    private static final Color TEXT_PRIMARY = new Color(30, 41, 59);    // #1e293b - Dark Gray
    private static final Color TEXT_SECONDARY = new Color(100, 116, 139); // #64748b - Gray
    private static final Color TEXT_MUTED = new Color(148, 163, 184);   // #94a3b8 - Light Gray
    private static final Color ACCENT = new Color(59, 130, 246);        // #3b82f6 - Blue
    private static final Color ACCENT_HOVER = new Color(37, 99, 235);   // #2563eb - Darker Blue
    private static final Color SUCCESS = new Color(34, 197, 94);        // #22c55e - Green
    private static final Color WARNING = new Color(245, 158, 11);       // #f59e0b - Orange
    private static final Color DANGER = new Color(239, 68, 68);         // #ef4444 - Red
    private static final Color BORDER_COLOR = new Color(226, 232, 240); // #e2e8f0 - Light Border
    
    // IDOR Results Tab UI Components
    private JPanel mainPanel;
    private JTable resultsTable;
    private DefaultTableModel tableModel;
    private JTextArea originalRequestArea;
    private JTextArea originalResponseArea;
    private JTextArea selectedRequestArea;
    private JTextArea selectedResponseArea;
    private JLabel statusLabel;
    private JLabel originalInfoLabel;
    private JLabel originalBytesLabel;
    private JLabel selectedBytesLabel;
    private JProgressBar progressBar;
    private JLabel testCountLabel;
    
    // Store IDOR test results
    private List<IDORTestResult> currentResults;
    private IHttpRequestResponse originalRequest;
    private byte[] originalResponse;
    
    // ==================== Real Time IDOR Settings ====================
    private boolean realTimeIdorEnabled = false;
    private String realTimeAuthHeader = "";
    private String realTimeDomainFilter = "all"; // "all", "select", "input"
    private String realTimeDomain = "";
    
    // Real Time IDOR UI Components
    private JCheckBox realTimeEnableCheckbox;
    private JTextArea realTimeAuthInput;
    private JComboBox<String> domainDropdown;
    private JTable realTimeResultsTable;
    private DefaultTableModel realTimeTableModel;
    private JLabel realTimeStatsLabel;
    private JPanel mainContentPanel;
    private CardLayout cardLayout;
    
    // Real Time IDOR Stats
    private int bypassedCount = 0;
    private int normalCount = 0;
    private List<RealTimeResult> realTimeResults = new ArrayList<>();
    
    // Real Time IDOR Request/Response viewers
    private JTextArea rtOriginalRequestArea;
    private JTextArea rtOriginalResponseArea;
    private JTextArea rtModifiedRequestArea;
    private JTextArea rtModifiedResponseArea;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // Initialize request history storage
        this.requestHistoryByColor = new HashMap<>();
        this.authHeadersByColor = new HashMap<>();
        this.authHeaderTimestamps = new HashMap<>();
        for (String color : COLORS) {
            requestHistoryByColor.put(color, new ArrayList<>());
        }
        
        // Initialize results storage
        this.currentResults = new ArrayList<>();
        
        // Create UI
        SwingUtilities.invokeLater(() -> {
            createUI();
            callbacks.addSuiteTab(BurpExtender.this);
        });

        callbacks.setExtensionName("ZeroX");
        callbacks.registerExtensionStateListener(this);
        callbacks.registerProxyListener(this);
        callbacks.registerHttpListener(this);
        callbacks.registerContextMenuFactory(this);
        stdout.println("ZeroX Loaded - IDOR Auto-Tester Ready");
    }
    
    // ==================== ITab Implementation ====================
    
    @Override
    public String getTabCaption() {
        return "ZeroX";
    }
    
    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
    
    private void createUI() {
        mainPanel = new JPanel(new BorderLayout(0, 0));
        mainPanel.setBackground(BG_PRIMARY);
        
        // ==================== Header Panel ====================
        JPanel headerPanel = createHeaderPanel();
        mainPanel.add(headerPanel, BorderLayout.NORTH);
        
        // ==================== Tab Switcher ====================
        JPanel tabSwitcher = createTabSwitcher();
        
        // ==================== Main Content with CardLayout ====================
        cardLayout = new CardLayout();
        mainContentPanel = new JPanel(cardLayout);
        mainContentPanel.setBackground(BG_PRIMARY);
        
        // Automate IDOR Panel
        JPanel automatePanel = createAutomateIDORPanel();
        mainContentPanel.add(automatePanel, "automate");
        
        // Real Time IDOR Panel
        JPanel realTimePanel = createRealTimeIDORPanel();
        mainContentPanel.add(realTimePanel, "realtime");
        
        // Content wrapper
        JPanel contentWrapper = new JPanel(new BorderLayout(0, 0));
        contentWrapper.setBackground(BG_PRIMARY);
        contentWrapper.add(tabSwitcher, BorderLayout.NORTH);
        contentWrapper.add(mainContentPanel, BorderLayout.CENTER);
        
        mainPanel.add(contentWrapper, BorderLayout.CENTER);
        
        // ==================== Status Bar ====================
        JPanel statusBar = createStatusBar();
        mainPanel.add(statusBar, BorderLayout.SOUTH);
    }
    
    private JPanel createTabSwitcher() {
        JPanel container = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        container.setBackground(BG_PRIMARY);
        container.setBorder(new EmptyBorder(8, 16, 12, 16));
        
        JPanel pillContainer = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        pillContainer.setBackground(BG_SECONDARY);
        pillContainer.setBorder(BorderFactory.createCompoundBorder(
            new LineBorder(BORDER_COLOR, 1, true),
            new EmptyBorder(4, 4, 4, 4)
        ));
        
        JButton automateTab = createPillButton("Automate BAC", true);
        JButton realTimeTab = createPillButton("Real Time BAC", false);
        
        automateTab.addActionListener(e -> {
            cardLayout.show(mainContentPanel, "automate");
            automateTab.setBackground(ACCENT);
            automateTab.setForeground(Color.WHITE);
            realTimeTab.setBackground(BG_PRIMARY);
            realTimeTab.setForeground(TEXT_SECONDARY);
        });
        
        realTimeTab.addActionListener(e -> {
            cardLayout.show(mainContentPanel, "realtime");
            realTimeTab.setBackground(ACCENT);
            realTimeTab.setForeground(Color.WHITE);
            automateTab.setBackground(BG_PRIMARY);
            automateTab.setForeground(TEXT_SECONDARY);
        });
        
        pillContainer.add(automateTab);
        pillContainer.add(realTimeTab);
        container.add(pillContainer);
        
        return container;
    }
    
    private JButton createPillButton(String text, boolean isSelected) {
        JButton button = new JButton(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2d.setColor(getBackground());
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 16, 16);
                g2d.setColor(getForeground());
                g2d.setFont(getFont());
                FontMetrics fm = g2d.getFontMetrics();
                int x = (getWidth() - fm.stringWidth(getText())) / 2;
                int y = ((getHeight() - fm.getHeight()) / 2) + fm.getAscent();
                g2d.drawString(getText(), x, y);
            }
        };
        button.setFont(new Font("Segoe UI", Font.BOLD, 11));
        button.setPreferredSize(new Dimension(115, 32));
        button.setBorderPainted(false);
        button.setContentAreaFilled(false);
        button.setFocusPainted(false);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        
        if (isSelected) {
            button.setBackground(ACCENT);
            button.setForeground(Color.WHITE);
        } else {
            button.setBackground(BG_PRIMARY);
            button.setForeground(TEXT_SECONDARY);
        }
        
        return button;
    }
    
    private JPanel createAutomateIDORPanel() {
        JPanel contentPanel = new JPanel(new BorderLayout(12, 12));
        contentPanel.setBackground(BG_PRIMARY);
        contentPanel.setBorder(new EmptyBorder(12, 16, 12, 16));
        
        // Results Table Card
        JPanel tableCard = createTableCard();
        
        // Request/Response Panels
        JPanel viewersPanel = createViewersPanel();
        
        // Main split between table and viewers
        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        verticalSplit.setBackground(BG_PRIMARY);
        verticalSplit.setBorder(null);
        verticalSplit.setDividerSize(8);
        verticalSplit.setResizeWeight(0.35);
        verticalSplit.setTopComponent(tableCard);
        verticalSplit.setBottomComponent(viewersPanel);
        
        contentPanel.add(verticalSplit, BorderLayout.CENTER);
        
        return contentPanel;
    }
    
    private JPanel createRealTimeIDORPanel() {
        JPanel panel = new JPanel(new BorderLayout(12, 12));
        panel.setBackground(BG_PRIMARY);
        panel.setBorder(new EmptyBorder(8, 16, 8, 16));
        
        // Top section - Settings
        JPanel settingsCard = new JPanel(new BorderLayout(0, 16));
        settingsCard.setBackground(BG_CARD);
        settingsCard.setBorder(BorderFactory.createCompoundBorder(
            new LineBorder(BORDER_COLOR, 1, true),
            new EmptyBorder(16, 20, 16, 20)
        ));
        
        // Toggle row
        JPanel toggleRow = new JPanel(new BorderLayout());
        toggleRow.setOpaque(false);
        
        JLabel toggleLabel = new JLabel("Real Time BAC");
        toggleLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        toggleLabel.setForeground(TEXT_PRIMARY);
        toggleRow.add(toggleLabel, BorderLayout.WEST);
        
        // Custom toggle switch
        JPanel toggleSwitch = createToggleSwitch();
        toggleRow.add(toggleSwitch, BorderLayout.EAST);
        
        settingsCard.add(toggleRow, BorderLayout.NORTH);
        
        // Settings content
        JPanel settingsContent = new JPanel();
        settingsContent.setLayout(new BoxLayout(settingsContent, BoxLayout.Y_AXIS));
        settingsContent.setOpaque(false);
        
        // Auth header section
        JPanel authSection = new JPanel(new BorderLayout(0, 6));
        authSection.setOpaque(false);
        authSection.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        JLabel authLabel = new JLabel("Authorization Header");
        authLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        authLabel.setForeground(TEXT_SECONDARY);
        authSection.add(authLabel, BorderLayout.NORTH);
        
        realTimeAuthInput = new JTextArea(2, 40);
        realTimeAuthInput.setFont(new Font("Consolas", Font.PLAIN, 12));
        realTimeAuthInput.setBackground(BG_SECONDARY);
        realTimeAuthInput.setForeground(TEXT_PRIMARY);
        realTimeAuthInput.setCaretColor(ACCENT);
        realTimeAuthInput.setBorder(new EmptyBorder(10, 12, 10, 12));
        realTimeAuthInput.setLineWrap(true);
        realTimeAuthInput.setText("Authorization: Bearer ");
        realTimeAuthInput.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateAuthHeader(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateAuthHeader(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateAuthHeader(); }
            private void updateAuthHeader() {
                realTimeAuthHeader = realTimeAuthInput.getText().trim();
            }
        });
        
        JScrollPane authScroll = new JScrollPane(realTimeAuthInput);
        authScroll.setBorder(BorderFactory.createCompoundBorder(
            new LineBorder(BORDER_COLOR, 1, true),
            new EmptyBorder(0, 0, 0, 0)
        ));
        authScroll.setPreferredSize(new Dimension(0, 56));
        authScroll.setMinimumSize(new Dimension(0, 56));
        authScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 56));
        authSection.add(authScroll, BorderLayout.CENTER);
        
        settingsContent.add(authSection);
        settingsContent.add(Box.createVerticalStrut(14));
        
        // Domain filter section
        JPanel domainSection = new JPanel(new BorderLayout(0, 8));
        domainSection.setOpaque(false);
        domainSection.setAlignmentX(Component.LEFT_ALIGNMENT);
        domainSection.setMinimumSize(new Dimension(0, 70));
        domainSection.setPreferredSize(new Dimension(Integer.MAX_VALUE, 70));
        
        JLabel domainLabel = new JLabel("Domain Filter");
        domainLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        domainLabel.setForeground(TEXT_SECONDARY);
        domainSection.add(domainLabel, BorderLayout.NORTH);
        
        // Segmented control
        JPanel segmentedControl = createSegmentedControl();
        segmentedControl.setMinimumSize(new Dimension(0, 40));
        segmentedControl.setPreferredSize(new Dimension(Integer.MAX_VALUE, 40));
        domainSection.add(segmentedControl, BorderLayout.CENTER);
        
        // Domain dropdown (for select)
        domainDropdown = new JComboBox<>();
        domainDropdown.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        domainDropdown.setBackground(BG_SECONDARY);
        domainDropdown.setForeground(TEXT_PRIMARY);
        domainDropdown.setVisible(false);
        domainDropdown.addActionListener(e -> {
            if (domainDropdown.getSelectedItem() != null) {
                realTimeDomain = domainDropdown.getSelectedItem().toString();
            }
        });
        
        domainSection.add(domainDropdown, BorderLayout.SOUTH);
        
        settingsContent.add(domainSection);
        
        settingsCard.add(settingsContent, BorderLayout.CENTER);
        
        // Results section
        JPanel resultsCard = new JPanel(new BorderLayout(0, 0));
        resultsCard.setBackground(BG_CARD);
        resultsCard.setBorder(BorderFactory.createCompoundBorder(
            new LineBorder(BORDER_COLOR, 1, true),
            new EmptyBorder(0, 0, 0, 0)
        ));
        
        // Results header
        JPanel resultsHeader = new JPanel(new BorderLayout());
        resultsHeader.setBackground(BG_SECONDARY);
        resultsHeader.setBorder(new EmptyBorder(12, 16, 12, 16));
        
        JLabel resultsTitle = new JLabel("Results");
        resultsTitle.setFont(new Font("Segoe UI", Font.BOLD, 14));
        resultsTitle.setForeground(TEXT_PRIMARY);
        resultsHeader.add(resultsTitle, BorderLayout.WEST);
        
        JButton clearRtBtn = createModernButton("Clear", new Color(239, 68, 68));
        clearRtBtn.addActionListener(e -> clearRealTimeResults());
        resultsHeader.add(clearRtBtn, BorderLayout.EAST);
        
        resultsCard.add(resultsHeader, BorderLayout.NORTH);
        
        // Results table
        String[] rtColumnNames = {"URL", "Orig Status", "Mod Status", "Orig Bytes", "Mod Bytes", "Result"};
        realTimeTableModel = new DefaultTableModel(rtColumnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        realTimeResultsTable = new JTable(realTimeTableModel);
        realTimeResultsTable.setBackground(BG_PRIMARY);
        realTimeResultsTable.setForeground(TEXT_PRIMARY);
        realTimeResultsTable.setGridColor(BORDER_COLOR);
        realTimeResultsTable.setSelectionBackground(new Color(59, 130, 246, 30));
        realTimeResultsTable.setSelectionForeground(TEXT_PRIMARY);
        realTimeResultsTable.setRowHeight(34);
        realTimeResultsTable.setShowHorizontalLines(true);
        realTimeResultsTable.setShowVerticalLines(false);
        
        // Table header
        JTableHeader rtHeader = realTimeResultsTable.getTableHeader();
        rtHeader.setBackground(BG_SECONDARY);
        rtHeader.setForeground(TEXT_SECONDARY);
        rtHeader.setFont(new Font("Segoe UI", Font.BOLD, 11));
        rtHeader.setBorder(new LineBorder(BORDER_COLOR, 1));
        rtHeader.setPreferredSize(new Dimension(0, 38));
        
        // Custom renderer for status column
        realTimeResultsTable.setDefaultRenderer(Object.class, new RealTimeTableCellRenderer());
        
        // Column widths
        realTimeResultsTable.getColumnModel().getColumn(0).setPreferredWidth(250);
        realTimeResultsTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        realTimeResultsTable.getColumnModel().getColumn(2).setPreferredWidth(80);
        realTimeResultsTable.getColumnModel().getColumn(3).setPreferredWidth(80);
        realTimeResultsTable.getColumnModel().getColumn(4).setPreferredWidth(80);
        realTimeResultsTable.getColumnModel().getColumn(5).setPreferredWidth(90);
        
        JScrollPane rtTableScroll = new JScrollPane(realTimeResultsTable);
        rtTableScroll.setBackground(BG_CARD);
        rtTableScroll.setBorder(null);
        rtTableScroll.getViewport().setBackground(BG_CARD);
        
        resultsCard.add(rtTableScroll, BorderLayout.CENTER);
        
        // Stats bar
        JPanel statsBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 8));
        statsBar.setBackground(BG_SECONDARY);
        statsBar.setBorder(new EmptyBorder(4, 8, 4, 8));
        
        realTimeStatsLabel = new JLabel("● Bypassed: 0    ● Normal: 0    Total: 0 requests");
        realTimeStatsLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        realTimeStatsLabel.setForeground(TEXT_SECONDARY);
        statsBar.add(realTimeStatsLabel);
        
        resultsCard.add(statsBar, BorderLayout.SOUTH);
        
        // Selection listener for results table
        realTimeResultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateRealTimeResultDisplay();
            }
        });
        
        // Request/Response comparison panel
        JPanel comparisonPanel = createRealTimeComparisonPanel();
        
        // Set fixed size for settings card - must be enough for all content
        settingsCard.setMinimumSize(new Dimension(0, 350));
        settingsCard.setPreferredSize(new Dimension(0, 350));
        
        // Layout - Three sections
        JSplitPane topSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        topSplit.setBackground(BG_PRIMARY);
        topSplit.setBorder(null);
        topSplit.setDividerSize(6);
        topSplit.setResizeWeight(0.0); // Settings card won't resize
        topSplit.setTopComponent(settingsCard);
        topSplit.setBottomComponent(resultsCard);
        
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setBackground(BG_PRIMARY);
        mainSplit.setBorder(null);
        mainSplit.setDividerSize(6);
        mainSplit.setResizeWeight(0.4);
        mainSplit.setTopComponent(topSplit);
        mainSplit.setBottomComponent(comparisonPanel);
        
        panel.add(mainSplit, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createRealTimeComparisonPanel() {
        JPanel panel = new JPanel(new GridLayout(1, 2, 12, 0));
        panel.setBackground(BG_PRIMARY);
        
        // Original Request/Response Card
        JPanel originalCard = createRTViewerCard("Original", new Color(59, 130, 246), true);
        
        // Modified Request/Response Card
        JPanel modifiedCard = createRTViewerCard("Modified", new Color(249, 115, 22), false);
        
        panel.add(originalCard);
        panel.add(modifiedCard);
        
        return panel;
    }
    
    private JPanel createRTViewerCard(String title, Color accentColor, boolean isOriginal) {
        JPanel card = new JPanel(new BorderLayout(0, 0));
        card.setBackground(BG_CARD);
        card.setBorder(BorderFactory.createCompoundBorder(
            new LineBorder(BORDER_COLOR, 1, true),
            new EmptyBorder(0, 0, 0, 0)
        ));
        
        // Card header with accent stripe
        JPanel cardHeader = new JPanel(new BorderLayout()) {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                g.setColor(accentColor);
                g.fillRect(0, getHeight() - 3, getWidth(), 3);
            }
        };
        cardHeader.setBackground(BG_SECONDARY);
        cardHeader.setBorder(new EmptyBorder(8, 14, 8, 14));
        
        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        titleLabel.setForeground(TEXT_PRIMARY);
        cardHeader.add(titleLabel, BorderLayout.WEST);
        
        card.add(cardHeader, BorderLayout.NORTH);
        
        // Tabbed pane for Request/Response
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setBackground(BG_CARD);
        tabbedPane.setForeground(TEXT_PRIMARY);
        tabbedPane.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        tabbedPane.setUI(new javax.swing.plaf.basic.BasicTabbedPaneUI() {
            @Override
            protected void installDefaults() {
                super.installDefaults();
                highlight = BG_ELEVATED;
                lightHighlight = BG_ELEVATED;
                shadow = BORDER_COLOR;
                darkShadow = BORDER_COLOR;
                focus = BG_ELEVATED;
            }
            
            @Override
            protected void paintTabBackground(Graphics g, int tabPlacement, int tabIndex,
                    int x, int y, int w, int h, boolean isSelected) {
                Graphics2D g2d = (Graphics2D) g;
                g2d.setColor(isSelected ? BG_ELEVATED : BG_SECONDARY);
                g2d.fillRect(x, y, w, h);
            }
            
            @Override
            protected void paintContentBorder(Graphics g, int tabPlacement, int selectedIndex) {}
            
            @Override
            protected void paintFocusIndicator(Graphics g, int tabPlacement, Rectangle[] rects,
                    int tabIndex, Rectangle iconRect, Rectangle textRect, boolean isSelected) {}
        });
        
        // Request tab
        JTextArea requestArea = createCodeArea();
        JScrollPane reqScroll = new JScrollPane(requestArea);
        reqScroll.setBorder(null);
        reqScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        reqScroll.getViewport().setBackground(BG_SECONDARY);
        styleScrollPane(reqScroll);
        tabbedPane.addTab("Request", reqScroll);
        
        // Response tab
        JTextArea responseArea = createCodeArea();
        JScrollPane respScroll = new JScrollPane(responseArea);
        respScroll.setBorder(null);
        respScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        respScroll.getViewport().setBackground(BG_SECONDARY);
        styleScrollPane(respScroll);
        tabbedPane.addTab("Response", respScroll);
        
        if (isOriginal) {
            rtOriginalRequestArea = requestArea;
            rtOriginalResponseArea = responseArea;
        } else {
            rtModifiedRequestArea = requestArea;
            rtModifiedResponseArea = responseArea;
        }
        
        card.add(tabbedPane, BorderLayout.CENTER);
        
        return card;
    }
    
    private void updateRealTimeResultDisplay() {
        int selectedRow = realTimeResultsTable.getSelectedRow();
        if (selectedRow >= 0 && selectedRow < realTimeResults.size()) {
            RealTimeResult result = realTimeResults.get(selectedRow);
            if (result != null) {
                rtOriginalRequestArea.setText(result.originalRequest != null ? result.originalRequest : "");
                rtOriginalResponseArea.setText(result.originalResponse != null ? result.originalResponse : "");
                rtModifiedRequestArea.setText(result.modifiedRequest != null ? result.modifiedRequest : "");
                rtModifiedResponseArea.setText(result.modifiedResponse != null ? result.modifiedResponse : "");
                
                rtOriginalRequestArea.setCaretPosition(0);
                rtOriginalResponseArea.setCaretPosition(0);
                rtModifiedRequestArea.setCaretPosition(0);
                rtModifiedResponseArea.setCaretPosition(0);
            }
        }
    }
    
    private JPanel createToggleSwitch() {
        JPanel togglePanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        togglePanel.setOpaque(false);
        
        JButton toggle = new JButton() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                
                // Track - Blue when ON, light gray when OFF
                if (realTimeIdorEnabled) {
                    g2d.setColor(ACCENT);
                } else {
                    g2d.setColor(new Color(203, 213, 225)); // Light gray
                }
                g2d.fillRoundRect(0, 3, 48, 24, 24, 24);
                
                // Knob with shadow effect
                int knobX = realTimeIdorEnabled ? 26 : 2;
                g2d.setColor(new Color(0, 0, 0, 30));
                g2d.fillOval(knobX + 1, 6, 20, 20);
                g2d.setColor(Color.WHITE);
                g2d.fillOval(knobX, 5, 20, 20);
            }
        };
        toggle.setPreferredSize(new Dimension(48, 30));
        toggle.setBorderPainted(false);
        toggle.setContentAreaFilled(false);
        toggle.setFocusPainted(false);
        toggle.setCursor(new Cursor(Cursor.HAND_CURSOR));
        
        toggle.addActionListener(e -> {
            realTimeIdorEnabled = !realTimeIdorEnabled;
            toggle.repaint();
            if (realTimeIdorEnabled) {
                populateDomainDropdown();
            }
            stdout.println("[ZeroX] Real Time BAC: " + (realTimeIdorEnabled ? "ENABLED" : "DISABLED"));
        });
        
        togglePanel.add(toggle);
        return togglePanel;
    }
    
    private JPanel createSegmentedControl() {
        JPanel container = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        container.setOpaque(false);
        
        JPanel segmented = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        segmented.setBackground(BG_SECONDARY);
        segmented.setBorder(BorderFactory.createCompoundBorder(
            new LineBorder(BORDER_COLOR, 1, true),
            new EmptyBorder(3, 3, 3, 3)
        ));
        
        JButton allBtn = createSegmentButton("All", true);
        JButton selectBtn = createSegmentButton("Select", false);
        
        allBtn.addActionListener(e -> {
            realTimeDomainFilter = "all";
            allBtn.setBackground(ACCENT);
            allBtn.setForeground(Color.WHITE);
            selectBtn.setBackground(BG_PRIMARY);
            selectBtn.setForeground(TEXT_SECONDARY);
            domainDropdown.setVisible(false);
        });
        
        selectBtn.addActionListener(e -> {
            realTimeDomainFilter = "select";
            selectBtn.setBackground(ACCENT);
            selectBtn.setForeground(Color.WHITE);
            allBtn.setBackground(BG_PRIMARY);
            allBtn.setForeground(TEXT_SECONDARY);
            populateDomainDropdown();
            domainDropdown.setVisible(true);
        });
        
        segmented.add(allBtn);
        segmented.add(selectBtn);
        container.add(segmented);
        
        return container;
    }
    
    private JButton createSegmentButton(String text, boolean isSelected) {
        JButton button = new JButton(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2d.setColor(getBackground());
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 10, 10);
                g2d.setColor(getForeground());
                g2d.setFont(getFont());
                FontMetrics fm = g2d.getFontMetrics();
                int x = (getWidth() - fm.stringWidth(getText())) / 2;
                int y = ((getHeight() - fm.getHeight()) / 2) + fm.getAscent();
                g2d.drawString(getText(), x, y);
            }
        };
        button.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        button.setPreferredSize(new Dimension(75, 28));
        button.setBorderPainted(false);
        button.setContentAreaFilled(false);
        button.setFocusPainted(false);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        
        if (isSelected) {
            button.setBackground(ACCENT);
            button.setForeground(Color.WHITE);
        } else {
            button.setBackground(BG_PRIMARY);
            button.setForeground(TEXT_SECONDARY);
        }
        
        return button;
    }
    
    private void populateDomainDropdown() {
        domainDropdown.removeAllItems();
        java.util.Set<String> domains = new java.util.HashSet<>();
        
        IHttpRequestResponse[] proxyHistory = callbacks.getProxyHistory();
        if (proxyHistory != null) {
            int startIndex = Math.max(0, proxyHistory.length - 200);
            for (int i = proxyHistory.length - 1; i >= startIndex; i--) {
                IHttpRequestResponse item = proxyHistory[i];
                if (item == null) continue;
                
                IRequestInfo reqInfo = helpers.analyzeRequest(item);
                URL url = reqInfo.getUrl();
                if (url != null) {
                    domains.add(url.getHost());
                }
            }
        }
        
        for (String domain : domains) {
            domainDropdown.addItem(domain);
        }
    }
    
    private void clearRealTimeResults() {
        realTimeTableModel.setRowCount(0);
        realTimeResults.clear();
        bypassedCount = 0;
        normalCount = 0;
        updateRealTimeStats();
    }
    
    private void updateRealTimeStats() {
        SwingUtilities.invokeLater(() -> {
            realTimeStatsLabel.setText(String.format(
                "● Bypassed: %d    ● Normal: %d    Total: %d requests",
                bypassedCount, normalCount, bypassedCount + normalCount
            ));
        });
    }
    
    // Real Time table cell renderer
    private class RealTimeTableCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            
            JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            label.setBorder(new EmptyBorder(0, 12, 0, 12));
            label.setFont(new Font("Segoe UI", Font.PLAIN, 11));
            
            if (isSelected) {
                label.setBackground(new Color(59, 130, 246, 30));
                label.setForeground(TEXT_PRIMARY);
            } else {
                // Alternating row colors - white theme
                if (row % 2 == 0) {
                    label.setBackground(BG_PRIMARY);
                } else {
                    label.setBackground(BG_SECONDARY);
                }
                label.setForeground(TEXT_PRIMARY);
                
                // Status code columns (1 = Orig Status, 2 = Mod Status)
                if ((column == 1 || column == 2) && value != null) {
                    try {
                        int statusCode = Integer.parseInt(value.toString());
                        if (statusCode >= 200 && statusCode < 300) {
                            label.setForeground(SUCCESS); // Green for 2xx
                        } else if (statusCode == 401 || statusCode == 403) {
                            label.setForeground(WARNING); // Orange for 401/403
                        } else if (statusCode >= 400) {
                            label.setForeground(DANGER); // Red for other 4xx/5xx
                        }
                    } catch (NumberFormatException ignored) {}
                }
                
                // Bytes columns (3 = Orig Bytes, 4 = Mod Bytes)
                if ((column == 3 || column == 4) && value != null) {
                    label.setText(value.toString() + " B");
                }
                
                // Result column (5)
                if (column == 5 && value != null) {
                    String status = value.toString();
                    if ("BYPASSED".equals(status)) {
                        label.setForeground(DANGER);
                        label.setFont(new Font("Segoe UI", Font.BOLD, 11));
                        label.setText("● " + status);
                    } else {
                        label.setForeground(SUCCESS);
                        label.setFont(new Font("Segoe UI", Font.BOLD, 11));
                        label.setText("● " + status);
                    }
                }
            }
            
            return label;
        }
    }
    
    private JPanel createHeaderPanel() {
        JPanel header = new JPanel(new BorderLayout()) {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
                // White background with subtle blue accent at bottom
                g2d.setColor(BG_PRIMARY);
                g2d.fillRect(0, 0, getWidth(), getHeight());
                // Blue accent stripe at bottom
                g2d.setColor(ACCENT);
                g2d.fillRect(0, getHeight() - 3, getWidth(), 3);
            }
        };
        header.setPreferredSize(new Dimension(0, 72));
        header.setBorder(new EmptyBorder(14, 24, 14, 24));
        
        // Left side - Logo and Title
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        leftPanel.setOpaque(false);
        
        // Title and subtitle
        JPanel titlePanel = new JPanel();
        titlePanel.setLayout(new BoxLayout(titlePanel, BoxLayout.Y_AXIS));
        titlePanel.setOpaque(false);
        
        JLabel titleLabel = new JLabel("ZeroX BAC");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        titleLabel.setForeground(TEXT_PRIMARY);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        JLabel subtitleLabel = new JLabel("Broken Access Control Detection");
        subtitleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        subtitleLabel.setForeground(TEXT_SECONDARY);
        subtitleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        titlePanel.add(titleLabel);
        titlePanel.add(Box.createVerticalStrut(2));
        titlePanel.add(subtitleLabel);
        leftPanel.add(titlePanel);
        
        header.add(leftPanel, BorderLayout.WEST);
        
        // Right side - Info and status
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 16, 0));
        rightPanel.setOpaque(false);
        
        // Test count badge with blue background
        testCountLabel = new JLabel("0 Tests") {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2d.setColor(new Color(59, 130, 246, 20)); // Light blue background
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 16, 16);
                super.paintComponent(g);
            }
        };
        testCountLabel.setFont(new Font("Segoe UI", Font.BOLD, 11));
        testCountLabel.setForeground(ACCENT);
        testCountLabel.setBorder(new EmptyBorder(6, 14, 6, 14));
        rightPanel.add(testCountLabel);
        
        header.add(rightPanel, BorderLayout.EAST);
        
        // Hidden label for storing info (not displayed)
        originalInfoLabel = new JLabel("");
        originalInfoLabel.setVisible(false);
        
        return header;
    }
    
    private JPanel createTableCard() {
        JPanel card = new JPanel(new BorderLayout(0, 0));
        card.setBackground(BG_CARD);
        card.setBorder(BorderFactory.createCompoundBorder(
            new LineBorder(BORDER_COLOR, 1, true),
            new EmptyBorder(0, 0, 0, 0)
        ));
        
        // Card header
        JPanel cardHeader = new JPanel(new BorderLayout());
        cardHeader.setBackground(BG_SECONDARY);
        cardHeader.setBorder(new EmptyBorder(12, 16, 12, 16));
        
        JLabel cardTitle = new JLabel("Test Results");
        cardTitle.setFont(new Font("Segoe UI", Font.BOLD, 13));
        cardTitle.setForeground(TEXT_PRIMARY);
        cardHeader.add(cardTitle, BorderLayout.WEST);
        
        // Action buttons in header
        JPanel actionButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        actionButtons.setOpaque(false);
        
        JButton clearBtn = createModernButton("Clear", DANGER);
        clearBtn.addActionListener(e -> clearResults());
        
        JButton exportBtn = createModernButton("Export", ACCENT);
        exportBtn.addActionListener(e -> exportReport());
        
        actionButtons.add(clearBtn);
        actionButtons.add(exportBtn);
        cardHeader.add(actionButtons, BorderLayout.EAST);
        
        card.add(cardHeader, BorderLayout.NORTH);
        
        // Table
        String[] columnNames = {"Color", "Auth Header", "Status", "Length", "Similarity", "Risk"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                // Only Color column (index 0) is editable
                return column == 0;
            }
        };
        
        resultsTable = new JTable(tableModel);
        resultsTable.setBackground(BG_PRIMARY);
        resultsTable.setForeground(TEXT_PRIMARY);
        resultsTable.setGridColor(BORDER_COLOR);
        resultsTable.setSelectionBackground(new Color(59, 130, 246, 30));
        resultsTable.setSelectionForeground(TEXT_PRIMARY);
        resultsTable.setRowHeight(38);
        resultsTable.setShowHorizontalLines(true);
        resultsTable.setShowVerticalLines(false);
        resultsTable.setIntercellSpacing(new Dimension(0, 1));
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.getTableHeader().setReorderingAllowed(false);
        
        // Table header styling
        JTableHeader tableHeader = resultsTable.getTableHeader();
        tableHeader.setBackground(BG_SECONDARY);
        tableHeader.setForeground(TEXT_SECONDARY);
        tableHeader.setFont(new Font("Segoe UI", Font.BOLD, 11));
        tableHeader.setBorder(new LineBorder(BORDER_COLOR, 1));
        tableHeader.setPreferredSize(new Dimension(0, 40));
        
        // Custom cell renderer
        resultsTable.setDefaultRenderer(Object.class, new ModernTableCellRenderer());
        
        // Column widths
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(80);
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(250);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(70);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(80);
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(90);
        resultsTable.getColumnModel().getColumn(5).setPreferredWidth(80);
        
        // Table model listener for cell edits
        tableModel.addTableModelListener(e -> {
            if (e.getType() == javax.swing.event.TableModelEvent.UPDATE && e.getColumn() == 0) {
                int row = e.getFirstRow();
                if (row >= 0 && row < currentResults.size()) {
                    String newColor = (String) tableModel.getValueAt(row, 0);
                    currentResults.get(row).color = newColor;
                }
            }
        });
        
        // Selection listener
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateSelectedResultDisplay();
            }
        });
        
        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                updateSelectedResultDisplay();
            }
        });
        
        JScrollPane tableScroll = new JScrollPane(resultsTable);
        tableScroll.setBackground(BG_CARD);
        tableScroll.setBorder(null);
        tableScroll.getViewport().setBackground(BG_CARD);
        
        card.add(tableScroll, BorderLayout.CENTER);
        
        return card;
    }
    
    private JPanel createViewersPanel() {
        JPanel panel = new JPanel(new GridLayout(1, 2, 12, 0));
        panel.setBackground(BG_PRIMARY);
        
        // Original Request/Response Card
        JPanel originalCard = createViewerCard("Original Request/Response", 
            new Color(59, 130, 246), // Blue
            true);
        
        // Selected Test Result Card
        JPanel selectedCard = createViewerCard("Selected Test Result",
            new Color(249, 115, 22), // Orange
            false);
        
        panel.add(originalCard);
        panel.add(selectedCard);
        
        return panel;
    }
    
    private JPanel createViewerCard(String title, Color accentColor, boolean isOriginal) {
        JPanel card = new JPanel(new BorderLayout(0, 0));
        card.setBackground(BG_CARD);
        card.setBorder(BorderFactory.createCompoundBorder(
            new LineBorder(BORDER_COLOR, 1, true),
            new EmptyBorder(0, 0, 0, 0)
        ));
        
        // Card header with accent stripe
        JPanel cardHeader = new JPanel(new BorderLayout()) {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                g.setColor(accentColor);
                g.fillRect(0, getHeight() - 2, getWidth(), 2);
            }
        };
        cardHeader.setBackground(BG_SECONDARY);
        cardHeader.setBorder(new EmptyBorder(10, 14, 10, 14));
        
        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        titleLabel.setForeground(TEXT_PRIMARY);
        cardHeader.add(titleLabel, BorderLayout.WEST);
        
        // Bytes label
        JLabel bytesLabel = new JLabel("0 bytes | 0 bytes");
        bytesLabel.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        bytesLabel.setForeground(TEXT_MUTED);
        cardHeader.add(bytesLabel, BorderLayout.EAST);
        
        if (isOriginal) {
            originalBytesLabel = bytesLabel;
        } else {
            selectedBytesLabel = bytesLabel;
        }
        
        card.add(cardHeader, BorderLayout.NORTH);
        
        // Content area with tabs
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setBackground(BG_PRIMARY);
        tabbedPane.setForeground(TEXT_PRIMARY);
        tabbedPane.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        tabbedPane.setUI(new javax.swing.plaf.basic.BasicTabbedPaneUI() {
            @Override
            protected void installDefaults() {
                super.installDefaults();
                highlight = BG_SECONDARY;
                lightHighlight = BG_SECONDARY;
                shadow = BORDER_COLOR;
                darkShadow = BORDER_COLOR;
                focus = ACCENT;
            }
            
            @Override
            protected void paintTabBackground(Graphics g, int tabPlacement, int tabIndex,
                    int x, int y, int w, int h, boolean isSelected) {
                Graphics2D g2d = (Graphics2D) g;
                if (isSelected) {
                    g2d.setColor(BG_PRIMARY); // White when selected
                } else {
                    g2d.setColor(BG_SECONDARY); // Light gray when not selected
                }
                g2d.fillRect(x, y, w, h);
            }
            
            @Override
            protected void paintContentBorder(Graphics g, int tabPlacement, int selectedIndex) {
                // Don't paint content border
            }
            
            @Override
            protected void paintFocusIndicator(Graphics g, int tabPlacement, Rectangle[] rects,
                    int tabIndex, Rectangle iconRect, Rectangle textRect, boolean isSelected) {
                // Don't paint focus indicator
            }
        });
        
        // Request tab
        JTextArea requestArea = createCodeArea();
        JScrollPane reqScroll = new JScrollPane(requestArea);
        reqScroll.setBorder(null);
        reqScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        reqScroll.getViewport().setBackground(BG_SECONDARY);
        styleScrollPane(reqScroll);
        tabbedPane.addTab("Request", reqScroll);
        
        // Response tab
        JTextArea responseArea = createCodeArea();
        JScrollPane respScroll = new JScrollPane(responseArea);
        respScroll.setBorder(null);
        respScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        respScroll.getViewport().setBackground(BG_SECONDARY);
        styleScrollPane(respScroll);
        tabbedPane.addTab("Response", respScroll);
        
        if (isOriginal) {
            originalRequestArea = requestArea;
            originalResponseArea = responseArea;
        } else {
            selectedRequestArea = requestArea;
            selectedResponseArea = responseArea;
        }
        
        card.add(tabbedPane, BorderLayout.CENTER);
        
        return card;
    }
    
    private JTextArea createCodeArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setFont(new Font("Consolas", Font.PLAIN, 12));
        area.setBackground(BG_SECONDARY);
        area.setForeground(TEXT_PRIMARY);
        area.setCaretColor(ACCENT);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setMargin(new Insets(12, 14, 12, 14));
        // Light selection color for white theme
        area.setSelectionColor(new Color(59, 130, 246, 40)); // Light blue selection
        area.setSelectedTextColor(TEXT_PRIMARY);
        return area;
    }
    
    private void styleScrollPane(JScrollPane scrollPane) {
        scrollPane.getVerticalScrollBar().setUI(new ModernScrollBarUI());
        scrollPane.getVerticalScrollBar().setBackground(BG_SECONDARY);
    }
    
    private JPanel createStatusBar() {
        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBackground(BG_SECONDARY);
        statusBar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, BORDER_COLOR),
            new EmptyBorder(8, 16, 8, 16)
        ));
        statusBar.setPreferredSize(new Dimension(0, 38));
        
        // Left - Status text
        statusLabel = new JLabel("Right-click a request > ZeroX > Automate BAC to start");
        statusLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        statusLabel.setForeground(TEXT_SECONDARY);
        statusBar.add(statusLabel, BorderLayout.WEST);
        
        // Right - Progress bar
        progressBar = new JProgressBar();
        progressBar.setPreferredSize(new Dimension(150, 4));
        progressBar.setBackground(BORDER_COLOR);
        progressBar.setForeground(ACCENT);
        progressBar.setBorderPainted(false);
        progressBar.setVisible(false);
        
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        rightPanel.setOpaque(false);
        rightPanel.add(progressBar);
        statusBar.add(rightPanel, BorderLayout.EAST);
        
        return statusBar;
    }
    
    private JButton createModernButton(String text, Color color) {
        JButton button = new JButton(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                
                if (getModel().isPressed()) {
                    g2d.setColor(color.darker());
                } else if (getModel().isRollover()) {
                    g2d.setColor(color.brighter());
                } else {
                    g2d.setColor(color);
                }
                
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 6, 6);
                
                g2d.setColor(Color.WHITE);
                g2d.setFont(getFont());
                FontMetrics fm = g2d.getFontMetrics();
                int x = (getWidth() - fm.stringWidth(getText())) / 2;
                int y = ((getHeight() - fm.getHeight()) / 2) + fm.getAscent();
                g2d.drawString(getText(), x, y);
            }
        };
        button.setFont(new Font("Segoe UI", Font.BOLD, 11));
        button.setForeground(Color.WHITE);
        button.setPreferredSize(new Dimension(70, 28));
        button.setBorderPainted(false);
        button.setContentAreaFilled(false);
        button.setFocusPainted(false);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        return button;
    }
    
    // Custom table cell renderer
    private class ModernTableCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            
            JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            label.setBorder(new EmptyBorder(0, 12, 0, 12));
            label.setFont(new Font("Segoe UI", Font.PLAIN, 12));
            
            if (isSelected) {
                label.setBackground(new Color(59, 130, 246, 30));
                label.setForeground(TEXT_PRIMARY);
            } else {
                // Alternating row colors - white theme
                if (row % 2 == 0) {
                    label.setBackground(BG_PRIMARY);
                } else {
                    label.setBackground(BG_SECONDARY);
                }
                label.setForeground(TEXT_PRIMARY);
                
                // Color column - show colored badge
                if (column == 0 && value != null) {
                    String colorName = value.toString();
                    label.setForeground(getColorForName(colorName));
                    label.setFont(new Font("Segoe UI", Font.BOLD, 12));
                }
                
                // Risk column - show colored badge
                if (column == 5 && value != null) {
                    String risk = value.toString();
                    switch (risk) {
                        case "HIGH":
                            label.setForeground(DANGER);
                            label.setFont(new Font("Segoe UI", Font.BOLD, 12));
                            break;
                        case "MEDIUM":
                            label.setForeground(WARNING);
                            label.setFont(new Font("Segoe UI", Font.BOLD, 12));
                            break;
                        case "LOW":
                            label.setForeground(ACCENT);
                            break;
                        default:
                            label.setForeground(SUCCESS);
                            break;
                    }
                }
                
                // Status column coloring
                if (column == 2 && value != null) {
                    try {
                        int status = Integer.parseInt(value.toString());
                        if (status >= 200 && status < 300) {
                            label.setForeground(new Color(34, 197, 94));
                        } else if (status >= 400) {
                            label.setForeground(DANGER);
                        }
                    } catch (NumberFormatException ignored) {}
                }
            }
            
            return label;
        }
    }
    
    // Modern scrollbar UI
    private class ModernScrollBarUI extends javax.swing.plaf.basic.BasicScrollBarUI {
        @Override
        protected void configureScrollBarColors() {
            this.thumbColor = new Color(203, 213, 225); // Light gray thumb
            this.trackColor = BG_SECONDARY;
        }
        
        @Override
        protected JButton createDecreaseButton(int orientation) {
            return createZeroButton();
        }
        
        @Override
        protected JButton createIncreaseButton(int orientation) {
            return createZeroButton();
        }
        
        private JButton createZeroButton() {
            JButton button = new JButton();
            button.setPreferredSize(new Dimension(0, 0));
            return button;
        }
        
        @Override
        protected void paintThumb(Graphics g, JComponent c, Rectangle thumbBounds) {
            Graphics2D g2d = (Graphics2D) g;
            g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2d.setColor(thumbColor);
            g2d.fillRoundRect(thumbBounds.x + 2, thumbBounds.y, thumbBounds.width - 4, thumbBounds.height, 8, 8);
        }
        
        @Override
        protected void paintTrack(Graphics g, JComponent c, Rectangle trackBounds) {
            g.setColor(trackColor);
            g.fillRect(trackBounds.x, trackBounds.y, trackBounds.width, trackBounds.height);
        }
    }
    
    private void updateSelectedResultDisplay() {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow >= 0 && selectedRow < currentResults.size()) {
            IDORTestResult result = currentResults.get(selectedRow);
            if (result != null) {
                selectedRequestArea.setText(result.requestText);
                selectedResponseArea.setText(result.responseText);
                selectedRequestArea.setCaretPosition(0);
                selectedResponseArea.setCaretPosition(0);
                
                // Update bytes label
                int reqBytes = result.requestText != null ? result.requestText.getBytes().length : 0;
                int respBytes = result.responseText != null ? result.responseText.getBytes().length : 0;
                selectedBytesLabel.setText(String.format("%,d bytes | %,d bytes", reqBytes, respBytes));
                
                // Update status
                String riskColor = result.riskLevel.equals("HIGH") ? "⚠" : 
                                   result.riskLevel.equals("MEDIUM") ? "⚡" : "✓";
                statusLabel.setText(String.format("%s %s | Status: %d | Similarity: %.1f%% | Risk: %s",
                        riskColor, result.color.toUpperCase(), result.statusCode, result.similarity, result.riskLevel));
            }
        }
    }
    
    private void displaySelectedResult(IDORTestResult result) {
        if (result != null) {
            selectedRequestArea.setText(result.requestText);
            selectedResponseArea.setText(result.responseText);
            selectedRequestArea.setCaretPosition(0);
            selectedResponseArea.setCaretPosition(0);
        }
    }
    
    private void clearResults() {
        tableModel.setRowCount(0);
        currentResults.clear();
        originalRequestArea.setText("");
        originalResponseArea.setText("");
        selectedRequestArea.setText("");
        selectedResponseArea.setText("");
        originalInfoLabel.setText("Ready to test");
        statusLabel.setText("Right-click a request > ZeroX > Automate IDOR to start");
        originalBytesLabel.setText("0 bytes | 0 bytes");
        selectedBytesLabel.setText("0 bytes | 0 bytes");
        testCountLabel.setText("0 Tests");
        progressBar.setVisible(false);
    }
    
    private void exportReport() {
        if (currentResults.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "No results to export.", "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        
        StringBuilder report = new StringBuilder();
        report.append("╔══════════════════════════════════════════════════════════════╗\n");
        report.append("║              ZeroX IDOR Test Report                          ║\n");
        report.append("╚══════════════════════════════════════════════════════════════╝\n\n");
        report.append("Original Request Info:\n");
        report.append("─".repeat(60)).append("\n");
        report.append(originalInfoLabel.getText()).append("\n\n");
        report.append("Results Summary:\n");
        report.append("─".repeat(60)).append("\n");
        report.append(String.format("%-12s %-8s %-10s %-12s %-10s\n", "Color", "Status", "Length", "Similarity", "Risk"));
        report.append("─".repeat(60)).append("\n");
        
        for (IDORTestResult result : currentResults) {
            report.append(String.format("%-12s %-8d %-10d %-12.1f%% %-10s\n",
                    result.color, result.statusCode, result.contentLength, result.similarity, result.riskLevel));
        }
        
        report.append("\n\n═══════════════════════════════════════════════════════════════\n");
        report.append("                    Detailed Results\n");
        report.append("═══════════════════════════════════════════════════════════════\n\n");
        
        for (IDORTestResult result : currentResults) {
            report.append("┌─ ").append(result.color.toUpperCase()).append(" [").append(result.riskLevel).append("] ─────────────────────────────────────\n");
            report.append("│ Status: ").append(result.statusCode).append(" | Length: ").append(result.contentLength).append(" bytes\n");
            report.append("└────────────────────────────────────────────────────────────\n\n");
            report.append("REQUEST:\n").append(result.requestText).append("\n\n");
            report.append("RESPONSE:\n").append(result.responseText).append("\n\n");
            report.append("─".repeat(60)).append("\n\n");
        }
        
        // Show in dialog with dark theme
        JTextArea reportArea = new JTextArea(report.toString());
        reportArea.setEditable(false);
        reportArea.setFont(new Font("Consolas", Font.PLAIN, 11));
        reportArea.setBackground(new Color(24, 24, 36));
        reportArea.setForeground(new Color(212, 212, 212));
        reportArea.setCaretColor(SUCCESS);
        
        JScrollPane scrollPane = new JScrollPane(reportArea);
        scrollPane.setPreferredSize(new Dimension(750, 550));
        scrollPane.setBorder(new LineBorder(BORDER_COLOR, 1));
        
        JOptionPane.showMessageDialog(mainPanel, scrollPane, "IDOR Test Report", JOptionPane.PLAIN_MESSAGE);
    }

    @Override
    public void extensionUnloaded() {
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (!messageIsRequest) return;

        IHttpRequestResponse messageInfo = message.getMessageInfo();
        if (messageInfo != null) {

            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            byte[] body = new byte[messageInfo.getRequest().length - requestInfo.getBodyOffset()];
            System.arraycopy(messageInfo.getRequest(), requestInfo.getBodyOffset(), body, 0, body.length);
            
            List<String> headers = requestInfo.getHeaders();
            List<String> zeroXHeaders = new ArrayList<>();
            List<String> cleanHeaders = new ArrayList<>();
            
            for (String header : headers) {
                if (header.toLowerCase(Locale.getDefault()).startsWith("x-zerox-")) {
                    zeroXHeaders.add(header);
                } else {
                    cleanHeaders.add(header);
                }
            }

            String detectedColor = null;
            for (String header : zeroXHeaders) {
                String headerLower = header.toLowerCase(Locale.getDefault());
                if (headerLower.startsWith("x-zerox-color:")) {
                    String[] parts = header.split(":", 2);
                    if (parts.length == 2) {
                        detectedColor = parts[1].trim().toLowerCase();
                        stdout.println("[ZeroX] Detected color: " + detectedColor);
                        messageInfo.setHighlight(detectedColor);
                    }
                }
            }
            messageInfo.setRequest(helpers.buildHttpMessage(cleanHeaders, body));
            
            // Store request history and Authorization header
            if (detectedColor != null && !detectedColor.isEmpty()) {
                List<IHttpRequestResponse> history = requestHistoryByColor.get(detectedColor);
                if (history != null) {
                    if (history.size() >= 100) {
                        history.remove(0);
                    }
                    history.add(messageInfo);
                }
                
                // Store Authorization header for this color
                for (String header : cleanHeaders) {
                    if (header.toLowerCase(Locale.getDefault()).startsWith("authorization:")) {
                        authHeadersByColor.put(detectedColor, header);
                        authHeaderTimestamps.put(detectedColor, System.currentTimeMillis());
                        break;
                    }
                }
            }
            
            // ==================== Real Time IDOR Processing ====================
            if (realTimeIdorEnabled && !realTimeAuthHeader.isEmpty()) {
                processRealTimeIDOR(messageInfo);
            }
        }
    }
    
    private void processRealTimeIDOR(IHttpRequestResponse messageInfo) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            URL url = requestInfo.getUrl();
            
            // Check domain filter
            if (!matchesDomainFilter(url.getHost())) {
                return;
            }
            
            String urlPath = url.getPath();
            stdout.println("[ZeroX RT] Processing: " + urlPath);
            
            // Get original request
            byte[] originalRequestBytes = messageInfo.getRequest();
            IHttpService httpService = messageInfo.getHttpService();
            
            // Send original request first to get baseline
            IHttpRequestResponse originalResponse = callbacks.makeHttpRequest(httpService, originalRequestBytes);
            int originalBytes = originalResponse.getResponse() != null ? originalResponse.getResponse().length : 0;
            
            // Build modified request with new auth header
            List<String> headers = requestInfo.getHeaders();
            List<String> newHeaders = new ArrayList<>();
            boolean authReplaced = false;
            
            for (String header : headers) {
                if (header.toLowerCase(Locale.getDefault()).startsWith("authorization:")) {
                    newHeaders.add(realTimeAuthHeader);
                    authReplaced = true;
                } else {
                    newHeaders.add(header);
                }
            }
            
            // Add auth header if not present
            if (!authReplaced && !realTimeAuthHeader.isEmpty()) {
                newHeaders.add(1, realTimeAuthHeader);
            }
            
            // Get body
            byte[] body = new byte[originalRequestBytes.length - requestInfo.getBodyOffset()];
            System.arraycopy(originalRequestBytes, requestInfo.getBodyOffset(), body, 0, body.length);
            
            // Build and send modified request
            byte[] modifiedRequest = helpers.buildHttpMessage(newHeaders, body);
            IHttpRequestResponse modifiedResponseObj = callbacks.makeHttpRequest(httpService, modifiedRequest);
            int modifiedBytes = modifiedResponseObj.getResponse() != null ? modifiedResponseObj.getResponse().length : 0;
            
            // Get status codes
            IResponseInfo origRespInfo = originalResponse.getResponse() != null ? 
                    helpers.analyzeResponse(originalResponse.getResponse()) : null;
            IResponseInfo modRespInfo = modifiedResponseObj.getResponse() != null ? 
                    helpers.analyzeResponse(modifiedResponseObj.getResponse()) : null;
            int origStatus = origRespInfo != null ? origRespInfo.getStatusCode() : 0;
            int modStatus = modRespInfo != null ? modRespInfo.getStatusCode() : 0;
            
            // Get response bodies for comparison
            String origBody = "";
            String modBody = "";
            if (originalResponse.getResponse() != null && origRespInfo != null) {
                origBody = new String(originalResponse.getResponse()).substring(origRespInfo.getBodyOffset());
            }
            if (modifiedResponseObj.getResponse() != null && modRespInfo != null) {
                modBody = new String(modifiedResponseObj.getResponse()).substring(modRespInfo.getBodyOffset());
            }
            
            // Get request/response texts
            String origReqText = new String(originalRequestBytes);
            String origRespText = originalResponse.getResponse() != null ? new String(originalResponse.getResponse()) : "";
            String modReqText = new String(modifiedRequest);
            String modRespText = modifiedResponseObj.getResponse() != null ? new String(modifiedResponseObj.getResponse()) : "";
            
            // Create result
            RealTimeResult result = new RealTimeResult(urlPath, originalBytes, modifiedBytes,
                    origStatus, modStatus,
                    origReqText, origRespText, modReqText, modRespText,
                    origBody, modBody);
            realTimeResults.add(result);
            
            // Update stats
            if ("BYPASSED".equals(result.status)) {
                bypassedCount++;
            } else {
                normalCount++;
            }
            
            // Update UI
            SwingUtilities.invokeLater(() -> {
                realTimeTableModel.addRow(new Object[]{
                    result.url,
                    result.originalStatus,
                    result.modifiedStatus,
                    String.format("%,d", result.originalBytes),
                    String.format("%,d", result.modifiedBytes),
                    result.status
                });
                updateRealTimeStats();
            });
            
            stdout.println("[ZeroX RT] " + urlPath + " - Original: " + originalBytes + "B, Modified: " + modifiedBytes + "B -> " + result.status);
            
        } catch (Exception e) {
            stderr.println("[ZeroX RT] Error: " + e.getMessage());
        }
    }
    
    private boolean matchesDomainFilter(String host) {
        if ("all".equals(realTimeDomainFilter)) {
            return true;
        }
        
        if (realTimeDomain == null || realTimeDomain.isEmpty()) {
            return false;
        }
        
        // Support wildcard matching
        if (realTimeDomain.startsWith("*.")) {
            String suffix = realTimeDomain.substring(1);
            return host.endsWith(suffix);
        }
        
        return host.equalsIgnoreCase(realTimeDomain);
    }
    
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest && messageInfo != null) {
            String color = messageInfo.getHighlight();
            if (color != null && !color.isEmpty()) {
                List<IHttpRequestResponse> history = requestHistoryByColor.get(color);
                if (history != null) {
                    if (history.size() >= 100) {
                        history.remove(0);
                    }
                    history.add(messageInfo);
                }
            }
        }
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        int[] allowedContexts = {
            IContextMenuInvocation.CONTEXT_PROXY_HISTORY,
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS
        };
        
        boolean isAllowedContext = false;
        for (int context : allowedContexts) {
            if (invocation.getInvocationContext() == context) {
                isAllowedContext = true;
                break;
            }
        }
        
        if (!isAllowedContext) {
            return menuItems;
        }
        
        IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
        if (selectedMessages == null || selectedMessages.length == 0) {
            return menuItems;
        }
        
        // Create ZeroX submenu
        JMenu zeroXMenu = new JMenu("ZeroX");
        
        // Create "Select Auth" submenu
        JMenu selectColorMenu = new JMenu("Select Auth");
        for (String color : COLORS) {
            JMenuItem colorItem = createColoredMenuItem(color, selectedMessages[0]);
            selectColorMenu.add(colorItem);
        }
        zeroXMenu.add(selectColorMenu);
        
        // Add "Automated IDOR" menu item
        JMenuItem testIdorItem = new JMenuItem("Automate IDOR");
        testIdorItem.addActionListener(e -> runIDORTest(selectedMessages[0]));
        zeroXMenu.add(testIdorItem);
        
        // Add "Real Time IDOR" menu item
        JMenuItem realTimeItem = new JMenuItem("Real Time IDOR");
        realTimeItem.addActionListener(e -> {
            // Switch to Real Time tab
            if (cardLayout != null && mainContentPanel != null) {
                cardLayout.show(mainContentPanel, "realtime");
            }
        });
        zeroXMenu.add(realTimeItem);
        
        menuItems.add(zeroXMenu);
        
        return menuItems;
    }
    
    // ==================== IDOR Test Implementation ====================
    
    private void runIDORTest(IHttpRequestResponse request) {
        // Run in background thread
        new Thread(() -> {
            try {
                stdout.println("[ZeroX] Starting IDOR Test...");
                
                // Clear previous results and show progress
                SwingUtilities.invokeLater(() -> {
                    clearResults();
                    statusLabel.setText("⏳ Running IDOR test...");
                    progressBar.setVisible(true);
                    progressBar.setIndeterminate(true);
                });
                
                // Store original request
                originalRequest = request;
                IRequestInfo originalRequestInfo = helpers.analyzeRequest(request);
                String originalRequestText = new String(request.getRequest());
                
                // Get original Authorization header and color
                String originalAuthHeader = null;
                String originalColor = request.getHighlight();
                List<String> originalHeaders = originalRequestInfo.getHeaders();
                
                for (String header : originalHeaders) {
                    if (header.toLowerCase(Locale.getDefault()).startsWith("authorization:")) {
                        originalAuthHeader = header;
                        break;
                    }
                }
                
                // Get URL info
                URL url = originalRequestInfo.getUrl();
                String method = originalRequestInfo.getMethod();
                String urlPath = url.getPath();
                
                // Update UI with original request info
                String infoText = String.format("%s %s | %s", method, urlPath, 
                        originalColor != null ? originalColor.toUpperCase() : "NO COLOR");
                
                final int origReqBytes = originalRequestText.getBytes().length;
                SwingUtilities.invokeLater(() -> {
                    originalInfoLabel.setText(infoText);
                    originalRequestArea.setText(originalRequestText);
                    originalRequestArea.setCaretPosition(0);
                    originalBytesLabel.setText(String.format("%,d bytes | ...", origReqBytes));
                });
                
                // Make original request to get baseline response
                IHttpService httpService = request.getHttpService();
                byte[] originalResponseBytes = callbacks.makeHttpRequest(httpService, request.getRequest()).getResponse();
                originalResponse = originalResponseBytes;
                
                if (originalResponseBytes != null) {
                    String originalResponseText = new String(originalResponseBytes);
                    final int origRespBytes = originalResponseBytes.length;
                    final int origReqBytesForLabel = originalRequestText.getBytes().length;
                    SwingUtilities.invokeLater(() -> {
                        originalResponseArea.setText(originalResponseText);
                        originalResponseArea.setCaretPosition(0);
                        originalBytesLabel.setText(String.format("%,d bytes | %,d bytes", origReqBytesForLabel, origRespBytes));
                    });
                }
                
                IResponseInfo originalRespInfo = originalResponseBytes != null ? 
                        helpers.analyzeResponse(originalResponseBytes) : null;
                int originalStatus = originalRespInfo != null ? originalRespInfo.getStatusCode() : 0;
                int originalLength = originalResponseBytes != null ? originalResponseBytes.length : 0;
                String originalBody = originalResponseBytes != null ? 
                        new String(originalResponseBytes).substring(
                                originalRespInfo != null ? originalRespInfo.getBodyOffset() : 0) : "";
                
                // Collect all Authorization headers from different colors
                Map<String, String> authHeaders = collectAuthHeaders();
                
                if (authHeaders.isEmpty()) {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText("⚠ No Authorization headers found in proxy history");
                        progressBar.setVisible(false);
                    });
                    stdout.println("[ZeroX] No Authorization headers found for IDOR test");
                    return;
                }
                
                // Test with each Authorization header
                List<IDORTestResult> results = new ArrayList<>();
                int testCount = 0;
                
                for (Map.Entry<String, String> entry : authHeaders.entrySet()) {
                    String color = entry.getKey();
                    String authHeader = entry.getValue();
                    
                    // Skip if same as original
                    if (originalColor != null && originalColor.equals(color)) {
                        continue;
                    }
                    
                    testCount++;
                    final int currentTest = testCount;
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText(String.format("⏳ Testing %s... (%d/%d)", color, currentTest, authHeaders.size()));
                    });
                    
                    stdout.println("[ZeroX] Testing with color: " + color);
                    
                    // Build new request with different Authorization header
                    List<String> newHeaders = new ArrayList<>();
                    boolean authReplaced = false;
                    
                    for (String header : originalHeaders) {
                        if (header.toLowerCase(Locale.getDefault()).startsWith("authorization:")) {
                            newHeaders.add(authHeader);
                            authReplaced = true;
                        } else {
                            newHeaders.add(header);
                        }
                    }
                    
                    // If original had no auth header, add one
                    if (!authReplaced) {
                        newHeaders.add(1, authHeader);
                    }
                    
                    // Get body from original request
                    byte[] body = new byte[request.getRequest().length - originalRequestInfo.getBodyOffset()];
                    System.arraycopy(request.getRequest(), originalRequestInfo.getBodyOffset(), body, 0, body.length);
                    
                    // Build and send request
                    byte[] newRequest = helpers.buildHttpMessage(newHeaders, body);
                    IHttpRequestResponse testResponse = callbacks.makeHttpRequest(httpService, newRequest);
                    
                    // Analyze response
                    byte[] responseBytes = testResponse.getResponse();
                    IResponseInfo respInfo = responseBytes != null ? helpers.analyzeResponse(responseBytes) : null;
                    
                    int statusCode = respInfo != null ? respInfo.getStatusCode() : 0;
                    int contentLength = responseBytes != null ? responseBytes.length : 0;
                    String responseBody = responseBytes != null ? 
                            new String(responseBytes).substring(respInfo != null ? respInfo.getBodyOffset() : 0) : "";
                    
                    // Calculate similarity
                    double similarity = calculateSimilarity(originalBody, responseBody);
                    
                    // Determine risk level
                    String riskLevel = determineRiskLevel(originalStatus, statusCode, similarity);
                    
                    // Create result
                    IDORTestResult result = new IDORTestResult();
                    result.color = color;
                    result.authHeader = authHeader.length() > 40 ? authHeader.substring(0, 40) + "..." : authHeader;
                    result.statusCode = statusCode;
                    result.contentLength = contentLength;
                    result.similarity = similarity;
                    result.riskLevel = riskLevel;
                    result.requestText = new String(newRequest);
                    result.responseText = responseBytes != null ? new String(responseBytes) : "No response";
                    
                    results.add(result);
                    
                    // Update table
                    final IDORTestResult finalResult = result;
                    SwingUtilities.invokeLater(() -> {
                        tableModel.addRow(new Object[]{
                                finalResult.color,
                                finalResult.authHeader,
                                finalResult.statusCode,
                                finalResult.contentLength,
                                String.format("%.1f%%", finalResult.similarity),
                                finalResult.riskLevel
                        });
                        currentResults.add(finalResult);
                        testCountLabel.setText(currentResults.size() + " Tests");
                    });
                }
                
                // Final status update
                long highRiskCount = results.stream().filter(r -> "HIGH".equals(r.riskLevel)).count();
                long mediumRiskCount = results.stream().filter(r -> "MEDIUM".equals(r.riskLevel)).count();
                
                String finalStatus = highRiskCount > 0 ? 
                    String.format("⚠ IDOR DETECTED! %d HIGH, %d MEDIUM risk", highRiskCount, mediumRiskCount) :
                    String.format("✓ Test complete. %d tests, %d medium risk", results.size(), mediumRiskCount);
                
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText(finalStatus);
                    progressBar.setVisible(false);
                });
                
                stdout.println("[ZeroX] IDOR Test complete: " + finalStatus);
                
                
            } catch (Exception e) {
                stderr.println("[ZeroX] Error during IDOR test: " + e.getMessage());
                e.printStackTrace(stderr);
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("❌ Error: " + e.getMessage());
                    progressBar.setVisible(false);
                });
            }
        }).start();
    }
    
    private Map<String, String> collectAuthHeaders() {
        Map<String, String> authHeaders = new HashMap<>();
        long currentTime = System.currentTimeMillis();
        
        // First, use stored auth headers (only if within 1 hour)
        for (Map.Entry<String, String> entry : authHeadersByColor.entrySet()) {
            String color = entry.getKey();
            Long timestamp = authHeaderTimestamps.get(color);
            
            if (timestamp != null && (currentTime - timestamp) <= MAX_AUTH_AGE_MS) {
                authHeaders.put(color, entry.getValue());
                long ageMinutes = (currentTime - timestamp) / (60 * 1000);
                stdout.println("[ZeroX] Using cached auth for " + color + " (age: " + ageMinutes + " min)");
            } else if (timestamp != null) {
                long ageMinutes = (currentTime - timestamp) / (60 * 1000);
                stdout.println("[ZeroX] Skipping expired auth for " + color + " (age: " + ageMinutes + " min, max: 60 min)");
            }
        }
        
        // Then search proxy history for any missing colors
        IHttpRequestResponse[] proxyHistory = callbacks.getProxyHistory();
        if (proxyHistory != null) {
            int startIndex = Math.max(0, proxyHistory.length - 500);
            
            for (int i = proxyHistory.length - 1; i >= startIndex; i--) {
                IHttpRequestResponse item = proxyHistory[i];
                if (item == null) continue;
                
                String color = item.getHighlight();
                if (color == null || color.isEmpty()) continue;
                
                if (authHeaders.containsKey(color)) continue;
                
                IRequestInfo reqInfo = helpers.analyzeRequest(item);
                List<String> headers = reqInfo.getHeaders();
                
                for (String header : headers) {
                    if (header.toLowerCase(Locale.getDefault()).startsWith("authorization:")) {
                        authHeaders.put(color, header);
                        stdout.println("[ZeroX] Found auth for " + color + " from proxy history");
                        break;
                    }
                }
            }
        }
        
        return authHeaders;
    }
    
    private double calculateSimilarity(String s1, String s2) {
        if (s1 == null || s2 == null) return 0.0;
        if (s1.isEmpty() && s2.isEmpty()) return 100.0;
        if (s1.isEmpty() || s2.isEmpty()) return 0.0;
        if (s1.equals(s2)) return 100.0;
        
        String[] tokens1 = s1.split("\\s+");
        String[] tokens2 = s2.split("\\s+");
        
        java.util.Set<String> set1 = new java.util.HashSet<>(java.util.Arrays.asList(tokens1));
        java.util.Set<String> set2 = new java.util.HashSet<>(java.util.Arrays.asList(tokens2));
        
        java.util.Set<String> intersection = new java.util.HashSet<>(set1);
        intersection.retainAll(set2);
        
        java.util.Set<String> union = new java.util.HashSet<>(set1);
        union.addAll(set2);
        
        if (union.isEmpty()) return 0.0;
        
        return (intersection.size() * 100.0) / union.size();
    }
    
    private String determineRiskLevel(int originalStatus, int testStatus, double similarity) {
        if (originalStatus >= 200 && originalStatus < 300) {
            if (testStatus >= 200 && testStatus < 300) {
                if (similarity >= 90.0) {
                    return "HIGH";
                } else if (similarity >= 50.0) {
                    return "MEDIUM";
                } else {
                    return "LOW";
                }
            } else if (testStatus == 401 || testStatus == 403) {
                return "NONE";
            } else {
                return "LOW";
            }
        }
        return "NONE";
    }
    
    // ==================== Authorization Header Replacement ====================
    
    private void replaceAuthorizationHeader(IHttpRequestResponse currentRequest, String targetColor) {
        try {
            IRequestInfo currentRequestInfo = helpers.analyzeRequest(currentRequest);
            List<String> currentHeaders = currentRequestInfo.getHeaders();
            String currentAuthHeader = null;
            
            for (String header : currentHeaders) {
                if (header.toLowerCase(Locale.getDefault()).startsWith("authorization:")) {
                    currentAuthHeader = header;
                    break;
                }
            }
            
            if (currentAuthHeader == null) {
                stdout.println("[ZeroX] No Authorization header found in current request");
                return;
            }
            
            String targetAuthHeader = authHeadersByColor.get(targetColor);
            
            if (targetAuthHeader == null) {
            List<IHttpRequestResponse> history = requestHistoryByColor.get(targetColor);
            
            if (history != null && !history.isEmpty()) {
                for (int i = history.size() - 1; i >= 0; i--) {
                    IHttpRequestResponse candidate = history.get(i);
                    IRequestInfo candidateInfo = helpers.analyzeRequest(candidate);
                    List<String> candidateHeaders = candidateInfo.getHeaders();
                    
                    for (String header : candidateHeaders) {
                        if (header.toLowerCase(Locale.getDefault()).startsWith("authorization:")) {
                            targetAuthHeader = header;
                            break;
                        }
                    }
                    
                        if (targetAuthHeader != null) break;
                    }
                }
            }
            
            if (targetAuthHeader == null) {
                IHttpRequestResponse[] proxyHistory = callbacks.getProxyHistory();
                if (proxyHistory != null) {
                    for (int i = proxyHistory.length - 1; i >= 0; i--) {
                        IHttpRequestResponse candidate = proxyHistory[i];
                        if (candidate == null) continue;
                        
                        String candidateColor = candidate.getHighlight();
                        if (targetColor.equals(candidateColor)) {
                            IRequestInfo candidateInfo = helpers.analyzeRequest(candidate);
                            List<String> candidateHeaders = candidateInfo.getHeaders();
                            
                            for (String header : candidateHeaders) {
                                if (header.toLowerCase(Locale.getDefault()).startsWith("authorization:")) {
                                    targetAuthHeader = header;
                                    break;
                                }
                            }
                            
                            if (targetAuthHeader != null) break;
                        }
                    }
                }
            }
            
            if (targetAuthHeader == null) {
                stdout.println("[ZeroX] No Authorization header found in requests with color: " + targetColor);
                return;
            }
            
            List<String> newHeaders = new ArrayList<>();
            for (String header : currentHeaders) {
                if (header.toLowerCase(Locale.getDefault()).startsWith("authorization:")) {
                    newHeaders.add(targetAuthHeader);
                } else {
                    newHeaders.add(header);
                }
            }
            
            byte[] currentRequestBytes = currentRequest.getRequest();
            byte[] body = new byte[currentRequestBytes.length - currentRequestInfo.getBodyOffset()];
            System.arraycopy(currentRequestBytes, currentRequestInfo.getBodyOffset(), body, 0, body.length);
            
            byte[] newRequest = helpers.buildHttpMessage(newHeaders, body);
            currentRequest.setRequest(newRequest);
            
            stdout.println("[ZeroX] Authorization header replaced from color: " + targetColor);
            stdout.println("[ZeroX] Old: " + currentAuthHeader);
            stdout.println("[ZeroX] New: " + targetAuthHeader);
            
        } catch (Exception e) {
            stderr.println("[ZeroX] Error replacing Authorization header: " + e.getMessage());
            e.printStackTrace(stderr);
        }
    }
    
    private JMenuItem createColoredMenuItem(String colorName, IHttpRequestResponse selectedMessage) {
        Color bgColor = getColorForName(colorName);
        Color fgColor = getContrastColor(bgColor);
        
        JMenuItem menuItem = new JMenuItem(colorName);
        menuItem.setBackground(bgColor);
        menuItem.setForeground(fgColor);
        menuItem.setOpaque(true);
        menuItem.setBorderPainted(false);
        
        menuItem.addActionListener(e -> {
            replaceAuthorizationHeader(selectedMessage, colorName);
        });
        
        return menuItem;
    }
    
    private Color getColorForName(String colorName) {
        switch (colorName.toLowerCase()) {
            case "red":
                return new Color(239, 68, 68);
            case "orange":
                return new Color(249, 115, 22);
            case "yellow":
                return new Color(234, 179, 8);
            case "green":
                return new Color(34, 197, 94);
            case "cyan":
                return new Color(20, 184, 166);
            case "blue":
                return new Color(59, 130, 246);
            case "purple":
                return new Color(168, 85, 247);
            case "pink":
                return new Color(236, 72, 153);
            default:
                return Color.LIGHT_GRAY;
        }
    }
    
    private Color getContrastColor(Color backgroundColor) {
        double luminance = (0.299 * backgroundColor.getRed() + 
                           0.587 * backgroundColor.getGreen() + 
                           0.114 * backgroundColor.getBlue()) / 255;
        return luminance > 0.5 ? Color.BLACK : Color.WHITE;
    }
    
    // ==================== IDOR Test Result Class ====================
    
    private static class IDORTestResult {
        String color;
        String authHeader;
        int statusCode;
        int contentLength;
        double similarity;
        String riskLevel;
        String requestText;
        String responseText;
    }
    
    // ==================== Real Time IDOR Result Class ====================
    
    private static class RealTimeResult {
        String url;
        int originalBytes;
        int modifiedBytes;
        int originalStatus;
        int modifiedStatus;
        String status; // "BYPASSED" or "NORMAL"
        long timestamp;
        String originalRequest;
        String originalResponse;
        String modifiedRequest;
        String modifiedResponse;
        String originalBody;
        String modifiedBody;
        
        RealTimeResult(String url, int originalBytes, int modifiedBytes,
                       int origStatus, int modStatus,
                       String origReq, String origResp, String modReq, String modResp,
                       String origBody, String modBody) {
            this.url = url;
            this.originalBytes = originalBytes;
            this.modifiedBytes = modifiedBytes;
            this.originalStatus = origStatus;
            this.modifiedStatus = modStatus;
            this.timestamp = System.currentTimeMillis();
            this.originalRequest = origReq;
            this.originalResponse = origResp;
            this.modifiedRequest = modReq;
            this.modifiedResponse = modResp;
            this.originalBody = origBody;
            this.modifiedBody = modBody;
            
            // BYPASSED: modified response is 200 AND body is same as original
            // NORMAL: modified response is 401/403 or body is different
            if (modStatus >= 200 && modStatus < 300 && origBody != null && origBody.equals(modBody)) {
                this.status = "BYPASSED";
            } else {
                this.status = "NORMAL";
            }
        }
    }
}

package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.swing.JMenuItem;
import javax.swing.JMenu;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

public class ZeroXContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final SessionManager sessionManager;
    private final ZeroXMatrixTab matrixTab;
    private final ExecutorService executor = Executors.newFixedThreadPool(10);

    public ZeroXContextMenuProvider(MontoyaApi api, SessionManager sessionManager, ZeroXMatrixTab matrixTab) {
        this.api = api;
        this.sessionManager = sessionManager;
        this.matrixTab = matrixTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // --- Legacy "Select Auth" Submenu ---
        JMenu selectAuthMenu = new JMenu("Select Auth");
        for (HighlightColor color : HighlightColor.values()) {
            if (color == HighlightColor.NONE) continue;
            if (!sessionManager.hasToken(color)) continue;

            JMenuItem item = new JMenuItem(sessionManager.toColorName(color));
            item.addActionListener(e -> {
                event.messageEditorRequestResponse().ifPresent(ref -> {
                    String token = sessionManager.getAuthorization(color);
                    if (token != null) {
                        HttpRequest updated = ref.requestResponse().request().withUpdatedHeader("Authorization", token);
                        ref.setRequest(updated);
                        api.logging().logToOutput("[ZeroX] Replaced Authorization header with " + sessionManager.toColorName(color) + " token.");
                    }
                });
            });
            selectAuthMenu.add(item);
        }

        if (selectAuthMenu.getItemCount() > 0) {
            menuItems.add(selectAuthMenu);
        }

        // --- Generate Auth Matrix Action ---
        JMenuItem matrixItem = new JMenuItem("Generate Auth Matrix");
        matrixItem.addActionListener(e -> generateAuthMatrix(event));
        menuItems.add(matrixItem);

        return menuItems;
    }

    private void generateAuthMatrix(ContextMenuEvent event) {
        // Get the selected request/response
        HttpRequestResponse baseReqRes = event.messageEditorRequestResponse()
                .map(ref -> ref.requestResponse())
                .orElse(null);

        if (baseReqRes == null && !event.selectedRequestResponses().isEmpty()) {
            baseReqRes = event.selectedRequestResponses().get(0);
        }

        if (baseReqRes == null || baseReqRes.request() == null) {
            api.logging().logToOutput("[ZeroX] No request selected for Auth Matrix generation.");
            return;
        }

        HttpRequest baseRequest = baseReqRes.request();
        HighlightColor originalColor = baseReqRes.annotations().highlightColor();

        matrixTab.setStatus("Generating Auth Matrix...");

        // Determine active sessions (colors that have tokens)
        List<HighlightColor> activeColors = new ArrayList<>();
        for (HighlightColor color : HighlightColor.values()) {
            if (color != HighlightColor.NONE && sessionManager.hasToken(color)) {
                activeColors.add(color);
            }
        }

        if (activeColors.isEmpty()) {
            matrixTab.setStatus("No cached sessions found. Browse with Firefox Containers first.");
            JOptionPane.showMessageDialog(matrixTab, "No cached sessions found.\n\nBrowse with Firefox Containers (x-zerox-color) to populate sessions.", "ZeroX Info", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // Send original request (Unauthenticated / Baseline)
        // We remove Authorization header to simulate unauthenticated access
        HttpRequest unauthRequest = baseRequest.withRemovedHeader("Authorization");
        String unauthName = originalColor == HighlightColor.NONE ? "Unauthenticated (original)" : "Unauthenticated";
        sendAndRecord(unauthRequest, HighlightColor.NONE, unauthName, baseRequest);

        // Send requests for each active role
        for (HighlightColor color : activeColors) {
            String authHeader = sessionManager.getAuthorization(color);
            HttpRequest modifiedRequest = baseRequest.withUpdatedHeader("Authorization", authHeader);

            String roleName = sessionManager.toColorName(color);
            if (color == originalColor) {
                roleName += " (original)";
            }

            sendAndRecord(modifiedRequest, color, roleName, baseRequest);
        }
    }

    private void sendAndRecord(HttpRequest request, HighlightColor color, String roleName, HttpRequest baselineRequest) {
        matrixTab.setStatus("Sending as " + roleName + "...");

        CompletableFuture.runAsync(() -> {
            try {
                HttpRequestResponse httpReqRes = api.http().sendRequest(request);
                HttpResponse response = httpReqRes.response();

                int statusCode = response != null ? response.statusCode() : 0;
                int length = response != null ? response.body().length() : 0;

                // Calculate similarity against baseline response (if available)
                int similarity = 0;
                if (baselineRequest != null) {
                    HttpRequestResponse baselineHttpReqRes = api.http().sendRequest(baselineRequest.withRemovedHeader("Authorization"));
                    HttpResponse baselineResponse = baselineHttpReqRes.response();
                    int baselineLength = baselineResponse != null ? baselineResponse.body().length() : 0;
                    if (baselineLength > 0) {
                        similarity = Math.round((float) length / baselineLength * 100);
                        if (similarity > 100) similarity = 200 - similarity; // clamp logic for overflow
                        if (similarity < 0) similarity = 0;
                    } else {
                        similarity = 100;
                    }
                } else {
                    similarity = 100;
                }

                String methodStr = request.method();
                String urlStr = request.path();
                if (request.httpService() != null) {
                    urlStr = request.httpService().host() + urlStr;
                }

                final String finalMethod = methodStr;
                final String finalUrl = urlStr;
                final int finalSimilarity = similarity;

                SwingUtilities.invokeLater(() -> {
                    // Update: pass the HttpRequestResponse object so the UI viewers can display it
                    matrixTab.addResult(httpReqRes, finalMethod, finalUrl, color, roleName, statusCode, length, finalSimilarity);
                    matrixTab.setStatus("Ready");
                });

            } catch (Exception ex) {
                api.logging().logToOutput("[ZeroX] Error sending request for " + roleName + ": " + ex.getMessage());
            }
        }, executor);
    }
}

package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class BurpExtender implements BurpExtension {

    private MontoyaApi api;
    private SessionManager sessionManager;
    private ZeroXHttpHandler httpHandler;
    private ZeroXContextMenuProvider contextMenuProvider;
    private ZeroXMatrixTab matrixTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.sessionManager = new SessionManager();
        this.httpHandler = new ZeroXHttpHandler(api, sessionManager);
        this.matrixTab = new ZeroXMatrixTab(api);
        this.contextMenuProvider = new ZeroXContextMenuProvider(api, sessionManager, matrixTab);

        api.extension().setName("ZeroX");

        // Register HTTP / Proxy handlers
        api.http().registerHttpHandler(httpHandler);
        api.proxy().registerRequestHandler(httpHandler);

        // Register UI Components
        api.userInterface().registerContextMenuItemsProvider(contextMenuProvider);
        api.userInterface().registerSuiteTab("ZeroX Matrix", matrixTab);

        api.logging().logToOutput("ZeroX - Loaded successfully with Montoya API");
        api.logging().logToOutput("Session Bridge & Auto-Pilot Sync Ready");
        api.logging().logToOutput("Auth Matrix Generator Ready");
    }
}

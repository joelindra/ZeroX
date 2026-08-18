package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;

public class ZeroXHttpHandler implements HttpHandler, ProxyRequestHandler {

    private final MontoyaApi api;
    private final SessionManager sessionManager;

    public ZeroXHttpHandler(MontoyaApi api, SessionManager sessionManager) {
        this.api = api;
        this.sessionManager = sessionManager;
    }

    // --- ProxyRequestHandler Implementation ---
    // Triggered for traffic going through the Proxy.
    // Used to read x-zerox-color, set the highlight color, and cache sessions.
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        HighlightColor detectedColor = HighlightColor.NONE;

        for (HttpHeader header : interceptedRequest.headers()) {
            if (header.name().equalsIgnoreCase("x-zerox-color")) {
                detectedColor = sessionManager.fromColorName(header.value());
                break;
            }
        }

        if (detectedColor != HighlightColor.NONE) {
            // Apply highlight color in Burp Proxy
            interceptedRequest.annotations().setHighlightColor(detectedColor);

            // Cache authorization & cookie headers in the session manager
            sessionManager.updateSession(detectedColor, interceptedRequest.headers());

            // Keep the x-zerox-color header intact so the original traffic is preserved perfectly
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

    // --- HttpHandler Implementation ---
    // Triggered for ALL HTTP requests made by Burp.
    // Used to execute the Auto-Pilot Session Sync for Repeater/Intruder.
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Only run for Repeater or Intruder requests
        if (requestToBeSent.toolSource().isFromTool(ToolType.REPEATER, ToolType.INTRUDER)) {
            HighlightColor color = requestToBeSent.annotations().highlightColor();
            if (color != HighlightColor.NONE && sessionManager.hasToken(color)) {
                HttpRequest modified = requestToBeSent;

                String authHeader = sessionManager.getAuthorization(color);
                String cookieHeader = sessionManager.getCookie(color);

                boolean replaced = false;

                if (authHeader != null && requestToBeSent.hasHeader("Authorization")) {
                    modified = modified.withUpdatedHeader("Authorization", authHeader);
                    replaced = true;
                }

                if (cookieHeader != null && requestToBeSent.hasHeader("Cookie")) {
                    modified = modified.withUpdatedHeader("Cookie", cookieHeader);
                    replaced = true;
                }

                if (replaced) {
                    api.logging().logToOutput("[ZeroX Auto-Pilot] Automatically updated session headers for request with highlight: " + sessionManager.toColorName(color));
                    return RequestToBeSentAction.continueWith(modified);
                }
            }
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}

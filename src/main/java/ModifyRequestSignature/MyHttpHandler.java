package ModifyRequestSignature;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.logging.Logging;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;

import utils.SignatureUtils;

import java.util.ArrayList;

public class MyHttpHandler implements HttpHandler
{
    private final MontoyaApi api;
    private final Logging logging;

    public MyHttpHandler(MontoyaApi api)
    {
        this.api = api;
        logging = api.logging();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {

        if (!ModifyRequestSignature.modificationEnabled || !httpRequestToBeSent.hasHeader(ModifyRequestSignature.header)) {
            return continueWith(httpRequestToBeSent);
        }

        if (httpRequestToBeSent.toolSource().toolType().toolName().equals("Proxy") && !api.proxy().isInterceptEnabled() && !ModifyRequestSignature.includeNonInterceptedRequestsButton.isSelected()) {
            return continueWith(httpRequestToBeSent);
        }

        String oldSignature = httpRequestToBeSent.headerValue(ModifyRequestSignature.header);
        String newSignature;
        try {
            newSignature = (String) SignatureUtils.calculateNewSignature(ModifyRequestSignature.algorithm, ModifyRequestSignature.field, ModifyRequestSignature.secret, httpRequestToBeSent.body().toString(), oldSignature).getFirst();
        } catch (Exception e) {
            logging.logToError("Error calculating new signature for " + httpRequestToBeSent.url() + " --- " + e.getMessage());
            return continueWith(httpRequestToBeSent);
        }

        return continueWith(httpRequestToBeSent.withUpdatedHeader(ModifyRequestSignature.header, newSignature));
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }
}
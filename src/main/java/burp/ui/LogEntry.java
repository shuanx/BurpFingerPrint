package burp.ui;

import burp.IHttpRequestResponsePersisted;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

public class LogEntry {
    final int id;
    IHttpRequestResponsePersisted requestResponse;
    String url;
    String method;
    String title;
    String status;
    String result;
    String resultDetail;
    String requestTime;

    public LogEntry(int id, IHttpRequestResponsePersisted requestResponse, String url, String method, Map<String, String> mapResult) {
        this.id = id;
        this.requestResponse = requestResponse;
        this.url = url;
        this.method = method;
        this.title = mapResult.get("title");
        this.status = mapResult.get("status");
        this.result = mapResult.get("result");
        this.resultDetail = mapResult.get("resultDetail");
        this.requestTime = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date());
    }

    public String getUrl(){
        return url;
    }

    public String getResult(){
        return result;
    }

    public String getDate(){
        return requestTime;
    }

    public String getResultDetail(){
        return resultDetail;
    }

    public void setResultDetail(String newResultDetail){
        resultDetail = newResultDetail;
    }

    public void setDate(String newDate){
        requestTime = newDate;
    }

    public void setResult(String newResult){
        result = newResult;
    }

    public void setRequestResponse(IHttpRequestResponsePersisted newRequestResponse){
        requestResponse = newRequestResponse;
    }

    public void setStatus(String newStatus){
        status = newStatus;
    }

}

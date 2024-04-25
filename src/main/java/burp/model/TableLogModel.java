package burp.model;

import burp.IHttpService;

public class TableLogModel {
    final int pid;
    int requestResponseIndex;
    Boolean isImportant;
    String url;
    String method;
    String title;
    String status;
    String result;
    String type;
    String resultInfo;
    String time;
    IHttpService iHttpService;

    public TableLogModel(int pid, String url, String method, String title, String status, String result, String type, Boolean isImportant, String resultInfo, IHttpService iHttpService, int requestResponseIndex, String time) {
        this.pid = pid;
        this.url = url;
        this.title = title;
        this.status = status;
        this.result = result;
        this.type = type;
        this.isImportant = isImportant;
        this.method = method;
        this.resultInfo = resultInfo;
        this.iHttpService = iHttpService;
        this.requestResponseIndex = requestResponseIndex;
        this.time = time;
    }

    public int getPid() {
        return pid;
    }

    public int getRequestResponseIndex() {
        return requestResponseIndex;
    }

    public void setRequestResponseIndex(int requestResponseIndex) {
        this.requestResponseIndex = requestResponseIndex;
    }

    public Boolean getIsImportant() {
        return isImportant;
    }

    public void setIsImportant(Boolean isImportant) {
        this.isImportant = isImportant;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getResultInfo() {
        return resultInfo;
    }

    public void setResultInfo(String resultInfo) {
        this.resultInfo = resultInfo;
    }

    public String getTime() {
        return time;
    }

    public void setTime(String time) {
        this.time = time;
    }

    public IHttpService getIHttpService() {
        return iHttpService;
    }

    public void setIHttpService(IHttpService iHttpService) {
        this.iHttpService = iHttpService;
    }

    public String getHost(){
        return this.iHttpService.getHost();
    }

    public int getPort(){
        return this.iHttpService.getPort();
    }

    public String getProtocol(){
        return this.iHttpService.getProtocol();
    }


}

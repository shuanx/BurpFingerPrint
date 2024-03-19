package burp.model;

import java.util.List;
/**
 * @author： shaun
 * @create： 2024/3/2 17:49
 * @description：TODO
 */
public class FingerPrintRule {
    private String cms;
    private String method;
    private String location;
    private List<String> keyword;
    // 新添加的构造函数
    public FingerPrintRule(String cms, String method, String location, List<String> keyword) {
        this.cms = cms;
        this.method = method;
        this.location = location;
        this.keyword = keyword;
    }

    public String getCms() {
        return cms;
    }

    public void setCms(String cms) {
        this.cms = cms;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public List<String> getKeyword() {
        return keyword;
    }

    public void setKeyword(List<String> keyword) {
        this.keyword = keyword;
    }

    public String getInfo(){
        return "cms: " + cms + "\r\nmethod: " + method + "\r\nlocation: " + location + "\r\nkeyword: " + keyword.toString();
    }
}

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
    private boolean isImportant;
    private String type;
    // 新添加的构造函数
    public FingerPrintRule(String type, boolean isImportant, String cms, String method, String location, List<String> keyword) {
        this.cms = cms;
        this.method = method;
        this.location = location;
        this.keyword = keyword;
        this.type = type;
        this.isImportant = isImportant;
    }
    public String getType(){return type;}
    public void setType(String type){this.cms = type;}
    public boolean getIsImportant(){return isImportant;}
    public void setIsImportant(boolean isImportant){this.isImportant = isImportant;}
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

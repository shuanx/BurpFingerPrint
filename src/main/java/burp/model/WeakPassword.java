package burp.model;

/**
 * Represents a weak password record.
 */
public class WeakPassword {
    private int id;
    private String url;
    private String finger;
    private String weakPassword;
    private String testNumber;
    private String resultInfo;
    private String status;
    private String time;
    private byte[] requestsByte = new byte[0];
    private byte[] responseByte = new byte[0];

    // Constructor with all fields
    public WeakPassword(int id, String url, String finger, String weakPassword,
                        String testNumber, String resultInfo, String status, String time) {
        this.id = id;
        this.url = url;
        this.finger = finger;
        this.weakPassword = weakPassword;
        this.testNumber = testNumber;
        this.resultInfo = resultInfo;
        this.status = status;
        this.time = time;
    }

    public WeakPassword(){

    }

    public byte[] getRequestsByte() {
        return requestsByte;
    }

    public byte[] getResponseByte() {
        return responseByte;
    }

    public void setRequestsByte(byte[] requestsByte) {
        this.requestsByte = requestsByte;
    }

    public void setResponseByte(byte[] responseByte) {
        this.responseByte = responseByte;
    }

    // Getters and setters for all fields
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getFinger() {
        return finger;
    }

    public void setFinger(String finger) {
        this.finger = finger;
    }

    public String getWeakPassword() {
        return weakPassword;
    }

    public void setWeakPassword(String weakPassword) {
        this.weakPassword = weakPassword;
    }

    public String getTestNumber() {
        return testNumber;
    }

    public void setTestNumber(String testNumber) {
        this.testNumber = testNumber;
    }

    public String getResultInfo() {
        return resultInfo;
    }

    public void setResultInfo(String resultInfo) {
        this.resultInfo = resultInfo;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getTime() {
        return time;
    }

    public void setTime(String time) {
        this.time = time;
    }

    // Overriding the toString() method for easy printing
    @Override
    public String toString() {
        return "WeakPassword{" +
                "id=" + id +
                ", url='" + url + '\'' +
                ", finger='" + finger + '\'' +
                ", weakPassword='" + weakPassword + '\'' +
                ", testNumber='" + testNumber + '\'' +
                ", resultInfo='" + resultInfo + '\'' +
                ", status='" + status + '\'' +
                ", time='" + time + '\'' +
                '}';
    }
}

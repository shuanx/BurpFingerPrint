package burp.weakpassword;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.model.WeakPassword;
import burp.util.Utils;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Arrays;
import java.util.Base64;

/**
 * @author： shaun
 * @create： 2024/5/4 16:11
 * @description：TODO
 */
public class TomcatWeakPassword {
    private static final String Finger = "Apache Tomcat";
    private static final List<String> weakCredentials = Arrays.asList(
            "tomcat:tomcat",
            "admin:admin",
            "tomcat:s3cret",
            "tomcat:password",
            "amdin:password"
    );

    private static Integer port = null;
    private static String protocol = null;
    private static String host = null;
    private static final String checkSuccessByBody = "Tomcat Web应用程序管理者";
    // 构造GET请求的字节数组
    static String tomcat_request = "GET /manager/html HTTP/1.1\r\n" +
            "Host: {host:port}\r\n" +
            "Authorization: Basic {payload}" + "\r\n" +
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36" + "\r\n" +
            "\r\n";

    public static WeakPassword checkWeakPasswords(WeakPassword wp) {
        String checkUrl = Utils.getUriFromUrl(wp.getUrl());
        StringBuilder result_info = new StringBuilder();
        try {
            // 创建URL对象
            URL url = new URL(checkUrl);
            // 获取protocol、host、port、path
            protocol = url.getProtocol();
            host = url.getHost();
            port = url.getPort();
            if (port == -1 && protocol.equalsIgnoreCase("http")){
                port = 80;
            } else if (port == -1 && protocol.equalsIgnoreCase("https")) {
                port = 443;
            }
        } catch (Exception e) {
            wp.setResultInfo("Invalid URL: " + checkUrl);
            return wp;
        }
        int testNumber = 0;
        for (String credential : weakCredentials) {
            testNumber += 1;
            String encodedCredential = Base64.getEncoder().encodeToString(credential.getBytes(StandardCharsets.UTF_8));
            String requests_data = tomcat_request.replace("{host:port}", host + ":" + port).replace("{payload}", encodedCredential);
            // 创建IHttpService对象
            IHttpService httpService = BurpExtender.getHelpers().buildHttpService(host, port, protocol);
            // 发起请求
            IHttpRequestResponse requestResponse = null;
            try {
                // 发起请求
                requestResponse = BurpExtender.getCallbacks().makeHttpRequest(httpService, requests_data.getBytes(StandardCharsets.UTF_8));
                // 空检查
                if (requestResponse == null || requestResponse.getResponse() == null) {
                    throw new IllegalStateException("Request failed, no response received.");
                }

                // 获取响应字节
                byte[] responseBytes = requestResponse.getResponse();
                String statusCode = String.valueOf(BurpExtender.getCallbacks().getHelpers().analyzeResponse(responseBytes).getStatusCode());
                if (checkSuccess(responseBytes)){
                    result_info.append("## 测试项：").append(credential).append("\r\n请求包为：\r\n").append(requests_data).append("\r\n响应包为：\r\n").append(new String(responseBytes.length > 10000 ? Arrays.copyOf(responseBytes, 10000) : responseBytes, StandardCharsets.UTF_8)).append("\r\n测试结果为： 爆破成功，状态码为：").append(statusCode).append("\r\n\r\n");
                    wp.setWeakPassword(credential);
                    wp.setStatus("爆破成功");
                    wp.setTestNumber(String.valueOf(testNumber));
                    wp.setRequestsByte(requests_data.getBytes());
                    wp.setResponseByte(responseBytes);
                    break;
                }
                result_info.append("## 测试项：").append(credential).append("\r\n请求包为：\r\n").append(requests_data).append("\r\n响应包为：\r\n").append(new String(responseBytes.length > 10000 ? Arrays.copyOf(responseBytes, 10000) : responseBytes, StandardCharsets.UTF_8)).append("\r\n测试结果为： 爆破失败，状态码为：").append(statusCode).append("\r\n\r\n");

            } catch (Exception e) {
                result_info.append("## 测试项：").append(credential).append("\r\n测试结果报错： ").append(e.getMessage()).append("\r\n\r\n");
            }
        }
        if (!wp.getStatus().equals("爆破成功")){
            wp.setStatus("爆破失败");
            wp.setRequestsByte(tomcat_request.getBytes());
            wp.setTestNumber(String.valueOf(weakCredentials.size()));
        }
        wp.setResultInfo(result_info.toString());

        return wp;

    }

    public static boolean checkSuccess(byte[] responseBytes){
        String responses = new String(responseBytes, StandardCharsets.UTF_8);
        if (responses.contains(checkSuccessByBody)){
            return true;
        }else{
            return false;
        }
    }
}


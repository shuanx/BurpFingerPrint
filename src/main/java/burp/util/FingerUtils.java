package burp.util;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpService;
import burp.IResponseInfo;
import burp.model.FingerPrintRule;
import burp.model.TableLogModel;
import burp.ui.FingerConfigTab;

import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * @author： shaun
 * @create： 2024/3/6 20:43
 * @description：TODO
 */
public class FingerUtils {
    public static TableLogModel FingerFilter(int pid, String oneUrl, byte[] oneResponseBytes, IHttpService iHttpService, IExtensionHelpers helpers, int requestResponseIndex){
        TableLogModel logModel = new TableLogModel(pid, oneUrl, "", "", "", "", "", false, "", iHttpService, requestResponseIndex);

        IResponseInfo responseInfo = helpers.analyzeResponse(oneResponseBytes);
        // 响应的body值
        String responseBody = new String(oneResponseBytes, StandardCharsets.UTF_8);
        // 响应的头部字段
        String responseHeaders = responseInfo.getHeaders().toString();
        // 提取title
        String responseTitle = Utils.getTitle(responseBody);
        // 提取mimeType
        String mimeType = responseInfo.getStatedMimeType().toLowerCase();
        if (responseTitle.isEmpty()) {
            responseTitle = responseBody;
        }
        String finalResponseTitle = responseTitle;

        String faviconHash = "0";

        if (finalResponseTitle.equals(responseBody)){
            logModel.setTitle("-");
        }
        else{
            logModel.setTitle(finalResponseTitle);
        }
        if (mimeType.contains("png") || mimeType.contains("jpeg") || mimeType.contains("icon") || mimeType.contains("image") || oneUrl.contains("favicon.") || oneUrl.contains(".ico")) {
            byte[] body = Arrays.copyOfRange(oneResponseBytes, responseInfo.getBodyOffset(), oneResponseBytes.length);
            faviconHash = Utils.getFaviconHash(body);
            BurpExtender.getStdout().println("The MurmurHash3 of the image is: " + oneUrl + ":" + faviconHash);
        }


        for (FingerPrintRule rule : BurpExtender.fingerprintRules) {
            // 看是否只对重点指纹进行匹配
            if (FingerConfigTab.allFingerprintsButton.isSelected() && !rule.getIsImportant()){
                continue;
            }
            String locationContent = "";
            if ("body".equals(rule.getLocation())) {
                locationContent = responseBody;
            } else if ("header".equals(rule.getLocation())) {
                locationContent = responseHeaders;
            } else if ("title".equals(rule.getLocation())) {
                locationContent = finalResponseTitle;
            }else{
                BurpExtender.getStderr().println("[!]指纹出现问题：" + rule.getLocation());
            }
            boolean allKeywordsPresent = true;
            if (mimeType.contains("png") || mimeType.contains("jpeg") || mimeType.contains("icon") || mimeType.contains("image") || oneUrl.contains("favicon.") || oneUrl.contains(".ico")) {
                // 进入图标匹配逻辑
                try {
                    if (!(faviconHash.equals(rule.getKeyword().get(0)))){
                        allKeywordsPresent = false;
                    }
                } catch (Exception e) {
                    BurpExtender.getStderr().println(e.getMessage());
                }
            }else{
                // 进入非图标匹配逻辑
                for (String keyword : rule.getKeyword()) {
                    if (!locationContent.contains(keyword)) {
                        allKeywordsPresent = false;
                        break;
                    }
                }
            }

            if (allKeywordsPresent) {
                if (!logModel.getResult().isEmpty()) {
                    // 如果result键已经存在，那么获取它的值并进行拼接
                    if (!logModel.getResult().contains(rule.getCms())){
                        logModel.setResult(logModel.getResult() + ", " + rule.getCms());
                    }
                } else {
                    // 如果result键不存在，那么直接添加新的result
                    logModel.setResult(rule.getCms());
                }
                String detailInfo =  "Time: " + new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()) + "\r\nUrl:" + oneUrl + "\r\n指纹详细信息如下：\r\n" + rule.getInfo();
                if (logModel.getResultInfo().isEmpty()){
                    // 如果resultDetail键已经存在，那么获取它的值并进行拼接
                    logModel.setResultInfo(detailInfo + "\r\n\r\n" + logModel.getResultInfo());
                }
                else{
                    // 如果resultDetail键不存在，那么直接添加新的result
                    logModel.setResultInfo(detailInfo);
                }
                if(logModel.getIsImportant()){
                    if (rule.getIsImportant()){
                        logModel.setIsImportant(rule.getIsImportant());
                    }
                } else{
                    logModel.setIsImportant(rule.getIsImportant());
                }
                if (!logModel.getType().isEmpty()) {
                    // 如果result键已经存在，那么获取它的值并进行拼接
                    if (logModel.getType().equals("-") && !rule.getType().equals("-")){
                        logModel.setType(rule.getType());
                    } else if (!logModel.getType().contains(rule.getType()) && !rule.getType().equals("-")) {
                        logModel.setType(logModel.getType() + ", " + rule.getType());
                    }
                } else {
                    // 如果result键不存在，那么直接添加新的result
                    logModel.setType(rule.getType());
                }
            }
        }
        return logModel;
    }
}

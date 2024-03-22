package burp.util;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IResponseInfo;
import burp.model.FingerPrintRule;

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
    public static Map<String, String> FingerFilter(String oneUrl, byte[] oneResponseBytes, IExtensionHelpers helpers){
        Map<String, String> mapResult =  new HashMap<String, String>();
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
            mapResult.put("title", "-");
        }
        else{
            mapResult.put("title", finalResponseTitle);
        }
        if (mimeType.contains("png") || mimeType.contains("jpeg") || mimeType.contains("icon") || mimeType.contains("image") || oneUrl.contains("favicon.") || oneUrl.contains(".ico")) {
            byte[] body = Arrays.copyOfRange(oneResponseBytes, responseInfo.getBodyOffset(), oneResponseBytes.length);
            faviconHash = Utils.getFaviconHash(body);
            BurpExtender.stdout.println("The MurmurHash3 of the image is: " + oneUrl + ":" + faviconHash);
        }


        for (FingerPrintRule rule : BurpExtender.fingerprintRules) {
            // 看是否只对重点指纹进行匹配
            if (BurpExtender.tags.fingerConfigTab.allFingerprintsButton.isSelected() && !rule.getIsImportant()){
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
                BurpExtender.stderr.println("[!]指纹出现问题：" + rule.getLocation());
            }
            boolean allKeywordsPresent = true;
            if (mimeType.contains("png") || mimeType.contains("jpeg") || mimeType.contains("icon") || mimeType.contains("image") || oneUrl.contains("favicon.") || oneUrl.contains(".ico")) {
                // 进入图标匹配逻辑
                try {
                    if (!(faviconHash.equals(rule.getKeyword().get(0)))){
                        allKeywordsPresent = false;
                    }
                } catch (Exception e) {
                    BurpExtender.stderr.println(e.getMessage());
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
                if (mapResult.containsKey("result")) {
                    // 如果result键已经存在，那么获取它的值并进行拼接
                    String existingResult = mapResult.get("result");
                    if (!existingResult.contains(rule.getCms())){
                        mapResult.put("result", existingResult + ", " + rule.getCms());
                    }
                } else {
                    // 如果result键不存在，那么直接添加新的result
                    mapResult.put("result", rule.getCms());
                }
                String detailInfo =  "Time: " + new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()) + "\r\nUrl:" + oneUrl + "\r\n指纹详细信息如下：\r\n" + rule.getInfo();
                if (mapResult.containsKey("resultDetail")){
                    // 如果resultDetail键已经存在，那么获取它的值并进行拼接
                    String existingResultDetail = mapResult.get("resultDetail");
                    mapResult.put("resultDetail", detailInfo + "\r\n\r\n" + existingResultDetail);
                }
                else{
                    // 如果resultDetail键不存在，那么直接添加新的result
                    mapResult.put("resultDetail", detailInfo);
                }
            }
        }
        return mapResult;
    }
}

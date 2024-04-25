package burp;

import burp.model.TableLogModel;
import burp.ui.FingerConfigTab;
import burp.ui.FingerTab;
import burp.util.FingerUtils;
import burp.util.HTTPUtils;
import burp.util.UrlScanCount;
import burp.util.Utils;

import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * @author： shaun
 * @create： 2024/4/5 09:07
 * @description：TODO
 */
public class IProxyScanner implements IProxyListener {
    private static UrlScanCount haveScanUrl = new UrlScanCount();
    public static int totalScanCount = 0;
    final ThreadPoolExecutor executorService;  // 修改这行
    private static IExtensionHelpers helpers;

    public IProxyScanner() {
        helpers = BurpExtender.getHelpers();
        // 先新建一个进程用于后续处理任务
        int coreCount = Runtime.getRuntime().availableProcessors();
        coreCount = Math.max(coreCount, 20);
        int maxPoolSize = coreCount * 2;
        BurpExtender.getStdout().println("[+] Number of threads enabled:: " + maxPoolSize);
        long keepAliveTime = 60L;
        executorService = new ThreadPoolExecutor(
                coreCount,
                maxPoolSize,
                keepAliveTime,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<Runnable>(), // 可以根据需要调整队列类型和大小
                Executors.defaultThreadFactory(),
                new ThreadPoolExecutor.CallerRunsPolicy() // 当线程池和队列都满时，任务在调用者线程中执行
        );
    }

    public static void setHaveScanUrlNew(){
        haveScanUrl = new UrlScanCount();
        FingerTab.lbSuccessCount.setText("0");
        FingerTab.lbRequestCount.setText("0");
        BurpExtender.getDataBaseService().clearRequestsResponseTable();
        BurpExtender.getDataBaseService().clearTableDataTable();
    }

    public void processProxyMessage(boolean messageIsRequest, final IInterceptedProxyMessage iInterceptedProxyMessage) {
        if (!messageIsRequest) {
            // 更新总数
            int newRequestsCount = Integer.parseInt(FingerTab.lbRequestCount.getText()) + 1;
            FingerTab.lbRequestCount.setText(Integer.toString(newRequestsCount));

            // 判断是否要进行指纹识别，如果关闭，则只展示数量
            if (FingerConfigTab.toggleButton.isSelected()){
                return;
            }

            IHttpRequestResponse requestResponse = iInterceptedProxyMessage.getMessageInfo();
            final IHttpRequestResponse resrsp = iInterceptedProxyMessage.getMessageInfo();
            String method = helpers.analyzeRequest(resrsp).getMethod();

            // 提取url，过滤掉静态文件
            String url = String.valueOf(helpers.analyzeRequest(resrsp).getUrl());
            if (Utils.isStaticFile(url) && !url.contains("favicon.") && !url.contains(".ico")){
                BurpExtender.getStdout().println("[+]静态文件，不进行url识别：" + url);
                return;
            }

            byte[] responseBytes = requestResponse.getResponse();

            // 网页提取URL并进行指纹识别
            executorService.submit(new Runnable() {
                @Override
                public void run() {

                    // 存储url和对应的response值
                    Map<String, Object> totalUrlResponse = new HashMap<String, Object>();

                    // 当前请求的URL，requests，Response，以及findUrl来区别是否为提取出来的URL
                    Map<String, Object> originalData = new HashMap<String, Object>();
                    originalData.put("responseRequest", requestResponse);
                    originalData.put("isFindUrl", false);
                    originalData.put("method", method);
                    totalUrlResponse.put(url, originalData);

                    if (!url.contains("favicon.") && !url.contains(".ico")) {
                        String mime = helpers.analyzeResponse(responseBytes).getInferredMimeType();
                        URL urlUrl = helpers.analyzeRequest(resrsp).getUrl();
                        // 针对html页面提取
                        Set<String> urlSet = new HashSet<>(Utils.extractUrlsFromHtml(url, new String(responseBytes)));
                        // 针对JS页面提取
                        if (mime.equals("script") || mime.equals("HTML") || url.contains(".htm") || Utils.isGetUrlExt(url)) {
                            urlSet.addAll(Utils.findUrl(urlUrl, new String(responseBytes)));
                        }
                        BurpExtender.getStdout().println("[+] 进入网页提取URL页面： " + url + "\r\n URL result: " + urlSet);

                        // 依次遍历urlSet获取其返回的response值
                        for (String getUrl : urlSet) {
                            totalUrlResponse.put(getUrl, HTTPUtils.makeGetRequest(getUrl));
                        }
                    }
                    BurpExtender.getStdout().println("[+]指纹识别开始： " + totalUrlResponse);

                    // 依次提取url和对应的response值进行指纹识别
                    for (Map.Entry<String, Object> entry : totalUrlResponse.entrySet()) {

                        String oneUrl = entry.getKey();
                        Object value = entry.getValue();
                        if (value instanceof Map) {
                            @SuppressWarnings("unchecked")
                            Map<String, Object> oneResult = (Map<String, Object>) value;
                            // Now it's safe to use oneResult
                            IHttpRequestResponse oneRequestsResponse = (IHttpRequestResponse) oneResult.get("responseRequest");
                            byte[] oneResponseBytes = oneRequestsResponse.getResponse();
                            int requestsResponseIndex = BurpExtender.getDataBaseService().insertOrUpdateRequestResponse(oneUrl, oneRequestsResponse.getRequest(), oneResponseBytes);
                            // 返回结果为空则退出
                            if (oneResponseBytes == null || oneResponseBytes.length == 0) {
                                BurpExtender.getStdout().println("返回结果为空: " + oneUrl);
                                continue;
                            }
                            String oneMethod = (String) oneResult.get("method");
                            IResponseInfo responseInfo = helpers.analyzeResponse(oneResponseBytes);

                            // 指纹识别并存储匹配结果
                            TableLogModel mapResult = FingerUtils.FingerFilter(iInterceptedProxyMessage.getMessageReference(), oneUrl, oneResponseBytes, oneRequestsResponse.getHttpService(), helpers, requestsResponseIndex);

                            // 无法识别出指纹的，则不添加
                            if (mapResult.getResult().isEmpty()) {
                                BurpExtender.getStdout().println("[+]无法识别指纹url: " + oneUrl);
                                continue;
                            }

                            mapResult.setStatus(Short.toString(responseInfo.getStatusCode()));
                            mapResult.setMethod(oneMethod);
                            BurpExtender.getDataBaseService().insertOrUpdateLogEntry(mapResult);
                            BurpExtender.getStdout().println(mapResult);
                        }
                        BurpExtender.getStdout().println("[END]指纹识别结束: " + totalUrlResponse);
                    }
                }
            });

            int waitingTasks = executorService.getQueue().size();  // 添加这行
            BurpExtender.getStdout().println(new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()) + ": 当前还有" + waitingTasks + " 个任务等待运行");  // 添加这行


        }

    }

}

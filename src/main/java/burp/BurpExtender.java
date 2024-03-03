package burp;

import burp.ui.LogEntry;
import burp.util.Utils;
import burp.ui.GUI;
import burp.Wrapper.FingerPrintRulesWrapper;
import burp.model.FingerPrintRule;

import java.awt.Component;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.Executors;
import javax.swing.*;
import com.google.gson.Gson;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.*;


public class BurpExtender implements IBurpExtender, ITab, IProxyListener {
    public final static String extensionName = "Finger Print";
    public final static String version = "v2024-03";
    public final static String author = "Shaun";
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public static BurpExtender burpExtender;
    private ThreadPoolExecutor executorService;  // 修改这行
    public static GUI gui;
    public static final List<LogEntry> log = new ArrayList<LogEntry>();
    private List<FingerPrintRule> fingerprintRules;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.burpExtender = this;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(),true);
        this.stderr = new PrintWriter(callbacks.getStderr(),true);

        //  注册菜单拓展
        callbacks.setExtensionName(extensionName + " " + version);
        BurpExtender.this.gui = new GUI();
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                // 添加一个标签页
                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);
                // 继承IProxyListener，必须进行注册，才能正常使用processProxyMessage模块
                BurpExtender.this.callbacks.registerProxyListener(BurpExtender.this);
                stdout.println(Utils.getBanner());
            }
        });
        // 先新建一个进程用于后续处理任务
        executorService = (ThreadPoolExecutor) Executors.newFixedThreadPool(10);  // 修改这行

        // 获取类加载器
        ClassLoader classLoader = getClass().getClassLoader();

        InputStream inputStream = classLoader.getResourceAsStream("conf/finger.json");
        if (inputStream == null) {
            stderr.println("[!] Failed to load the configuration file finger.json, because config/finger.json not found");
            return;
        }

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            Gson gson = new Gson();
            FingerPrintRulesWrapper rulesWrapper = gson.fromJson(reader, FingerPrintRulesWrapper.class);
            fingerprintRules = rulesWrapper.getFingerprint();
            stdout.println("[+] Successfully loaded the configuration file finger.json");
        } catch (IOException e) {
            stderr.println("[!] Failed to load the configuration file finger.json, because: " + e.getMessage());
        }
    }

    @Override
    public Component getUiComponent() {
        return gui.getComponet();
    }

    @Override
    public String getTabCaption() {
        return extensionName;
    }

    //    IHttpRequestResponse 接口包含了每个请求和响应的细节，在 brupsuite 中的每个请求或者响应都是 IHttpRequestResponse 实例。通过 getRequest()可以获取请求和响应的细节信息。
    public void processProxyMessage(boolean messageIsRequest, final IInterceptedProxyMessage iInterceptedProxyMessage) {
        if (!messageIsRequest) {
            // 更新总数
            int newRequestsCount = Integer.parseInt(GUI.lbRequestCount.getText()) + 1;
            GUI.lbRequestCount.setText(Integer.toString(newRequestsCount));
            IHttpRequestResponse requestResponse = iInterceptedProxyMessage.getMessageInfo();
            final IHttpRequestResponse resrsp = iInterceptedProxyMessage.getMessageInfo();
            // 提取url，过滤掉静态文件
            String url = String.valueOf(helpers.analyzeRequest(resrsp).getUrl());
            if (Utils.isStaticFile(url)){
                stdout.println("[+]静态文件，不进行url识别：" + url);
                return;
            }

            byte[] responseBytes = requestResponse.getResponse();
            IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
            // 响应的body值
            String responseBody = new String(responseBytes);
            // 响应的头部字段
            String responseHeaders = responseInfo.getHeaders().toString();
            // 提取title
            String responseTitle = Utils.getTitle(responseBody);
            boolean isGetTitle = true;
            if (responseTitle.isEmpty()) {
                responseTitle = responseBody;
                isGetTitle = false;
            }
            String finalResponseTitle = responseTitle;
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    synchronized(log) {
                        int row = log.size();
                        String method = helpers.analyzeRequest(resrsp).getMethod();
                        Map<String, String> mapResult =  new HashMap<String, String>();
                        if (finalResponseTitle.equals(responseBody)){
                            mapResult.put("title", "-");
                        }
                        else{
                            mapResult.put("title", finalResponseTitle);
                        }

                        for (FingerPrintRule rule : fingerprintRules) {
                            String locationContent = "";
                            if ("body".equals(rule.getLocation())) {
                                locationContent = responseBody;
                            } else if ("header".equals(rule.getLocation())) {
                                locationContent = responseHeaders;
                            } else if ("title".equals(rule.getLocation())) {
                                locationContent = finalResponseTitle;
                            }
                            boolean allKeywordsPresent = true;
                            for (String keyword : rule.getKeyword()) {
                                if (!locationContent.contains(keyword)) {
                                    allKeywordsPresent = false;
                                    break;
                                }
                            }
                            if (allKeywordsPresent) {
                                if (mapResult.containsKey("result")) {
                                    // 如果result键已经存在，那么获取它的值并进行拼接
                                    String existingResult = mapResult.get("result");
                                    mapResult.put("result", existingResult + ", " + rule.getCms());
                                } else {
                                    // 如果result键不存在，那么直接添加新的result
                                    mapResult.put("result", rule.getCms());
                                }
                                if (mapResult.containsKey("resultDetail")){
                                    // 如果resultDetail键已经存在，那么获取它的值并进行拼接
                                    String existingResultDetail = mapResult.get("resultDetail");
                                    mapResult.put("resultDetail", new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()) + "指纹详细信息如下：\r\n" + rule.getInfo() + "\r\n\r\n" + existingResultDetail);
                                }
                                else{
                                    // 如果resultDetail键不存在，那么直接添加新的result
                                    mapResult.put("resultDetail", new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()) + "指纹详细信息如下：\r\n" + rule.getInfo());
                                }
                            }
                        }

                        // 无法识别出指纹的，则不添加
                        if (!mapResult.containsKey("result")){
                            stdout.println("[+]无法识别指纹url: " + url);
                            return;
                        }

                        mapResult.put("status", Short.toString(responseInfo.getStatusCode()));

                        // 对log添加数据
                        if (!Utils.urlExistsInLog(log, Utils.getUriFromUrl(url))) {
                            log.add(0, new LogEntry(iInterceptedProxyMessage.getMessageReference(),
                                    callbacks.saveBuffersToTempFiles(resrsp), Utils.getUriFromUrl(url),
                                    method,
                                    mapResult)
                            );
                            int successRequestsCount = Integer.parseInt(GUI.lbSuccessCount.getText()) + 1;
                            GUI.lbSuccessCount.setText(Integer.toString(successRequestsCount));
                        }
                        else{
                            LogEntry existingEntry = null;
                            int existingIndex = -1;
                            for (int i = 0; i < log.size(); i++) {
                                LogEntry logEntry = log.get(i);
                                if (logEntry.getUrl().equals(Utils.getUriFromUrl(url))) {
                                    logEntry.setResult(logEntry.getResult() + ", " + mapResult.get("result"));
                                    logEntry.setDate(new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()));
                                    logEntry.setResultDetail(mapResult.get("resultDetail") + "\r\n\r\n" + logEntry.getResultDetail());
                                    if (Short.toString(responseInfo.getStatusCode()).equals("200")){
                                        logEntry.setStatus(Short.toString(responseInfo.getStatusCode()));
                                        logEntry.setRequestResponse(callbacks.saveBuffersToTempFiles(resrsp));
                                    }
                                    existingEntry = logEntry;  // 保存需要移动的条目
                                    existingIndex = i;  // 保存需要移动的条目的索引
                                    break;
                                }
                            }

                            // 如果找到了需要移动的条目，将其从列表中移除并添加到列表的开头
                            if (existingEntry != null) {
                                log.remove(existingIndex);
                                log.add(0, existingEntry);
                                GUI.logTable.getHttpLogTableModel().fireTableRowsUpdated(0, 0);
                                if (existingIndex + 1 < log.size()) {
                                    GUI.logTable.getHttpLogTableModel().fireTableRowsUpdated(existingIndex, existingIndex);
                                }
                            }
                        }
                        // 更新表格数据，表格数据对接log
                        GUI.logTable.getHttpLogTableModel().fireTableRowsInserted(row, row);
                    }
                }
            });
            int waitingTasks = executorService.getQueue().size();  // 添加这行
            stdout.println(new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()) + ": 当前还有" + waitingTasks + " 个任务等待运行");  // 添加这行


        }

    }


}
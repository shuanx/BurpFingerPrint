package burp;

import burp.model.TableLogModel;
import burp.model.WeakPassword;
import burp.ui.FingerTab;
import burp.ui.WeakPasswordTab;
import burp.util.FingerUtils;
import burp.util.HTTPUtils;
import burp.util.UrlScanCount;
import burp.util.Utils;
import burp.weakpassword.TomcatWeakPassword;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;

/**
 * @author： shaun
 * @create： 2024/4/5 09:07
 * @description：TODO
 */
public class IProxyScanner implements IProxyListener, IContextMenuFactory {
    private static UrlScanCount haveScanUrl = new UrlScanCount();
    public static int totalScanCount = 0;
    final ThreadPoolExecutor executorService;  // 修改这行
    private static IExtensionHelpers helpers;
    final ExecutorService monitorExecutorService;;  // 修改这行
    private static ScheduledExecutorService monitorExecutor;
    // 暴力破解模块支持指纹
    private static final List<String> WEAKPASSWORDMODEL = Arrays.asList("Tomcat");

    public IProxyScanner() {
        helpers = BurpExtender.getHelpers();
        // 先新建一个进程用于后续处理任务
        int coreCount = Runtime.getRuntime().availableProcessors();
        coreCount = Math.max(coreCount, 20);
        int maxPoolSize = coreCount * 2;
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
        BurpExtender.getStdout().println("[+] run executorService maxPoolSize: " + coreCount + " ~ " + maxPoolSize);

        monitorExecutorService = Executors.newFixedThreadPool(6); // 用固定数量的线程

        monitorExecutor = Executors.newSingleThreadScheduledExecutor();
        startDatabaseMonitor();
        BurpExtender.getStdout().println("[+] run Weak password blasting monitorExecutor success~ ");

        //注册右键菜单
        BurpExtender.getCallbacks().registerContextMenuFactory(this);//必须注册右键菜单Factory
    }

    private void startDatabaseMonitor() {
        monitorExecutor.scheduleAtFixedRate(() -> {
            monitorExecutorService.submit(() -> {
                try {
                    if (WeakPasswordTab.weakPasswordBlasting.isSelected()){
                        BurpExtender.getStdout().println("[-] 弱口令爆破模块关闭，不进行定时获取数据进行爆破。");
                        return;
                    }
                    WeakPassword wp = BurpExtender.getDataBaseService().fetchAndMarkSinglePathAsCrawling();
                    if (wp == null){
                        BurpExtender.getStdout().println("[*] 弱口令爆破模块运行中，但无需爆破的数据。");
                        return;
                    }
                    wp = TomcatWeakPassword.checkWeakPasswords(wp);
                    BurpExtender.getStdout().println("[+] url: " + wp.getUrl() + "爆破结果为: " + wp.getStatus());
                    BurpExtender.getDataBaseService().updateWeakPassword(wp);
                } catch (Exception e) {
                    BurpExtender.getStderr().println("[!] scheduleAtFixedRate error: ");
                    e.printStackTrace(BurpExtender.getStderr());
                }
            });
        }, 0, 10, TimeUnit.SECONDS);
    }

    public static void setHaveScanUrlNew(){
        haveScanUrl = new UrlScanCount();
        FingerTab.lbSuccessCount.setText("0");
        FingerTab.lbRequestCount.setText("0");
        BurpExtender.getDataBaseService().clearRequestsResponseTable();
        BurpExtender.getDataBaseService().clearTableDataTable();
        FingerTab.timer.stop();
    }

    public void processProxyMessage(boolean messageIsRequest, final IInterceptedProxyMessage iInterceptedProxyMessage) {
        if (!messageIsRequest) {
            // 更新总数
            FingerTab.lbRequestCount.setText(Integer.toString(BurpExtender.getDataBaseService().getTableDataCount()));

            final IHttpRequestResponse resrsp = iInterceptedProxyMessage.getMessageInfo();
            // 提取url，过滤掉静态文件
            String url = String.valueOf(helpers.analyzeRequest(resrsp).getUrl());
            if (Utils.isStaticFile(url) && !url.contains("favicon.") && !url.contains(".ico")){
                BurpExtender.getStdout().println("[+]静态文件，不进行url识别：" + url);
                return;
            }

            // 网页提取URL并进行指纹识别
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    fingerPrintIdentify(iInterceptedProxyMessage.getMessageReference(), iInterceptedProxyMessage.getMessageInfo());
                }
            });

            int waitingTasks = executorService.getQueue().size();  // 添加这行
            BurpExtender.getStdout().println(new SimpleDateFormat("[*] yyyy/MM/dd HH:mm:ss").format(new Date()) + ": 当前还有" + waitingTasks + " 个任务等待运行");  // 添加这行
        }

    }

    public static void shutdownMonitorExecutor() {
        // 关闭监控线程池
        if (monitorExecutor != null && !monitorExecutor.isShutdown()) {
            monitorExecutor.shutdown();
            try {
                // 等待线程池终止，设置一个合理的超时时间
                if (!monitorExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    // 如果线程池没有在规定时间内终止，则强制关闭
                    monitorExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                // 如果等待期间线程被中断，恢复中断状态
                Thread.currentThread().interrupt();
                // 强制关闭
                monitorExecutor.shutdownNow();
            }
        }
    }

    public static void ifInsertWeakPasswordDatabase(TableLogModel result){
        for (String value : WEAKPASSWORDMODEL){
            if (result.getResult().contains(value) && !BurpExtender.getDataBaseService().existsWeakPasswordByUrl(Utils.getUriFromUrl(result.getUrl()))){
                BurpExtender.getDataBaseService().insertWeakPassword(Utils.getUriFromUrl(result.getUrl()), value, "-", "-", "-", "等待爆破中", "-");
            }
        }
    }


    //实现右键
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        final IHttpRequestResponse[] iHttpRequestResponses = invocation.getSelectedMessages();
        JMenuItem i1 = new JMenuItem("Finger Print");
        i1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                for (final IHttpRequestResponse iHttpRequestResponse : iHttpRequestResponses) {
                    // 更新总数
                    FingerTab.lbRequestCount.setText(Integer.toString(BurpExtender.getDataBaseService().getTableDataCount()));
                    // 网页提取URL并进行指纹识别
                    executorService.submit(new Runnable() {
                        @Override
                        public void run() {
                            fingerPrintIdentify((int) System.currentTimeMillis(), iHttpRequestResponse);
                        }
                    });

                    int waitingTasks = executorService.getQueue().size();  // 添加这行
                    BurpExtender.getStdout().println(new SimpleDateFormat("[*] yyyy/MM/dd HH:mm:ss").format(new Date()) + ": 当前还有" + waitingTasks + " 个任务等待运行");  // 添加这行
                }
            }
        });

        return Arrays.asList(i1);
    }


    public static void fingerPrintIdentify(int pid,IHttpRequestResponse  requestResponse) {
        String method = helpers.analyzeRequest(requestResponse).getMethod();
        String url = String.valueOf(helpers.analyzeRequest(requestResponse).getUrl());
        BurpExtender.getStdout().println(String.format("[+] url : %s", url));

        // 存储url和对应的response值
        Map<String, Object> totalUrlResponse = new HashMap<String, Object>();

        // 当前请求的URL，requests，Response，以及findUrl来区别是否为提取出来的URL
        Map<String, Object> originalData = new HashMap<String, Object>();
        originalData.put("responseRequest", requestResponse);
        originalData.put("isFindUrl", false);
        originalData.put("method", method);
        totalUrlResponse.put(url, originalData);

        //获取请求信息的响应
        byte[] responseBytes = requestResponse.getResponse();

        if (!url.contains("favicon.") && !url.contains(".ico") && !FingerTab.toggleButton.isSelected()) {
            String mime = helpers.analyzeResponse(responseBytes).getInferredMimeType();
            URL urlUrl = helpers.analyzeRequest(requestResponse).getUrl();
            // 针对html页面提取
            Set<String> urlSet = new HashSet<>(Utils.extractUrlsFromHtml(url, new String(responseBytes)));
            // 针对JS页面提取
            if (mime.equals("script") || mime.equals("HTML") || url.contains(".htm") || Utils.isGetUrlExt(url)) {
                urlSet.addAll(Utils.findUrl(urlUrl, new String(responseBytes)));
            }
            BurpExtender.getStdout().println("[+] 进入网页提取URL页面： " + url + "\r\n    URL result: " + urlSet);

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
                TableLogModel mapResult = FingerUtils.FingerFilter(pid, oneUrl, oneResponseBytes, oneRequestsResponse.getHttpService(), helpers, requestsResponseIndex);

                // 无法识别出指纹的，则不添加
                if (mapResult.getResult().isEmpty()) {
                    BurpExtender.getStdout().println("[+]无法识别指纹url: " + oneUrl);
                    continue;
                }

                mapResult.setStatus(Short.toString(responseInfo.getStatusCode()));
                mapResult.setMethod(oneMethod);
                BurpExtender.getDataBaseService().insertOrUpdateLogEntry(mapResult);
                // 判断是否需要需要进行爆破
                ifInsertWeakPasswordDatabase(mapResult);
                //BurpExtender.getStdout().println(mapResult);
            }
            BurpExtender.getStdout().println("[END]指纹识别结束: " + totalUrlResponse);
        }
    }
}

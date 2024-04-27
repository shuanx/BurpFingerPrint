package burp.util;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpService;
import burp.model.TableLogModel;

import java.util.*;
import java.util.ArrayList;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.net.URL;
import java.io.*;
import java.net.*;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * @author： shaun
 * @create： 2024/2/18 21:11
 * @description：TODO
 */
public class Utils {
    // 静态文件直接过滤
    public final static String[] STATIC_FILE_EXT = new String[]{
            "png",
            "jpg",
            "jpeg",
            "gif",
            "pdf",
            "bmp",
            "css",
            "woff",
            "woff2",
            "ttf",
            "otf",
            "ttc",
            "svg",
            "psd",
            "exe",
            "zip",
            "rar",
            "7z",
            "msi",
            "tar",
            "gz",
            "mp3",
            "mp4",
            "mkv",
            "swf",
            "iso"
    };

    // 对以下URl提取URL
    public final static String[] STATIC_URl_EXT = new String[]{
            "js",
            "ppt",
            "pptx",
            "doc",
            "docx",
            "xls",
            "xlsx",
            "cvs"
    };

    // 不对下面URL进行指纹识别
    public final static  String[] UNCEKCK_DOMAINS = new String[]{
            ".baidu.com",
            ".google.com",
            ".bing.com",
            ".yahoo.com",
            ".aliyun.com",
            ".alibaba.com"
    };

    public static String getBanner(){
        String bannerInfo =
                "[+] " + BurpExtender.extensionName + " is loaded\n"
                        + "[+] #####################################\n"
                        + "[+] " + BurpExtender.extensionName + " v" + BurpExtender.version +"\n"
                        + "[+] anthor: " + BurpExtender.author + "\n"
                        + "[+] ####################################\n"
                        + "[+] Please enjoy it!";
        return bannerInfo;
    }

    public static boolean urlFilter(String url){
        return false;
    }

    public static String getTitle(String responseBody){
        Pattern pattern = Pattern.compile("<title>(.*?)</title>", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(responseBody);
        if (matcher.find()) {
            String responseTitle = matcher.group(1);
            return responseTitle;
        } else {
            return "";
        }
    }

    public static boolean isStaticFile(String url) {
        for (String ext : STATIC_FILE_EXT) {
            if (ext.equalsIgnoreCase(Utils.getUriExt(url))) return true;
        }
        return false;
    }

    public  static boolean isGetUrlExt(String url){
        for (String ext : STATIC_URl_EXT){
            if (ext.equalsIgnoreCase(Utils.getUriExt(url))) return true;
        }
        return false;
    }

    public static boolean isWhiteDomain(String url){
        for (String uncheckDomains : UNCEKCK_DOMAINS){
            if (url.contains(uncheckDomains)) return true;
        }
        return false;
    }


    public static String getUriExt(String url) {
        String pureUrl = url.substring(0, url.contains("?") ? url.indexOf("?") : url.length());
        return (pureUrl.lastIndexOf(".") > -1 ? pureUrl.substring(pureUrl.lastIndexOf(".") + 1) : "").toLowerCase();
    }

    public static boolean urlExistsInLog(List<TableLogModel> log, String url) {
        for (TableLogModel logEntry : log) {
            if (logEntry.getUrl().equals(url))
                return true;
        }
        return false;
    }

    public static String getUriFromUrl(String urlString)  {
        // 匹配 "https://xxx/" 或 "http://xxx/" 或 "https://xxx" 或 "http://xxx" 的正则表达式
        String regex = "(https?://[^/]+/?)(?=/|$)";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(urlString);

        if (matcher.find()) {
            return removeBackSlash(matcher.group(1));
        }
        else{
            return removeBackSlash(urlString);
        }
    }

    public static String removeBackSlash(String urlString){
        if (urlString.endsWith("/")) {
            return urlString.substring(0, urlString.length() - 1);
        } else {
            return urlString;
        }
    }

    public static String getFaviconHash(byte[] faviconBytes) {

            String base64Favicon = Base64.getEncoder().encodeToString(faviconBytes);

            // 格式化base64字符串
            String formattedBase64Favicon = formatBase64(base64Favicon);

            // 计算格式化后base64字符串的murmurHash3值
            return String.valueOf(murmurHash3_x86_32(formattedBase64Favicon.getBytes(), 0, formattedBase64Favicon.length(), 0));
    }

    public static int murmurHash3_x86_32(final byte[] data, int offset, int len, final int seed) {
        final int c1 = 0xcc9e2d51;
        final int c2 = 0x1b873593;

        int h1 = seed;
        final int roundedEnd = offset + (len & 0xfffffffc); // round down to 4 byte block

        for (int i = offset; i < roundedEnd; i += 4) {
            // little endian load order
            int k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24);
            k1 *= c1;
            k1 = Integer.rotateLeft(k1, 15);
            k1 *= c2;

            h1 ^= k1;
            h1 = Integer.rotateLeft(h1, 13);
            h1 = h1 * 5 + 0xe6546b64;
        }

        // handle the last few bytes of the input array
        int k1 = 0;
        switch (len & 0x03) {
            case 3:
                k1 = (data[roundedEnd + 2] & 0xff) << 16;
                // fall through
            case 2:
                k1 |= (data[roundedEnd + 1] & 0xff) << 8;
                // fall through
            case 1:
                k1 |= (data[roundedEnd] & 0xff);
                k1 *= c1;
                k1 = Integer.rotateLeft(k1, 15);
                k1 *= c2;
                h1 ^= k1;
        }

        // finalization
        h1 ^= len;

        // fmix
        h1 ^= h1 >>> 16;
        h1 *= 0x85ebca6b;
        h1 ^= h1 >>> 13;
        h1 *= 0xc2b2ae35;
        h1 ^= h1 >>> 16;

        return h1;
    }
    private static String formatBase64(String base64) {
        Pattern pattern = Pattern.compile(".{76}");
        Matcher matcher = pattern.matcher(base64);
        StringBuilder formattedBase64 = new StringBuilder();

        while (matcher.find()) {
            formattedBase64.append(matcher.group()).append("\n");
        }

        int remainder = base64.length() % 76;
        if (remainder > 0) {
            formattedBase64.append(base64.substring(base64.length() - remainder)).append("\n");
        }

        return formattedBase64.toString();
    }

    public static List<String> findUrl(URL url, String js)
    {
        String pattern_raw = "(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;|*()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/|;][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|)))(?:\"|')";
        Pattern r = Pattern.compile(pattern_raw);
        Matcher m = r.matcher(js);
        int matcher_start = 0;
        List<String> ex_urls = new ArrayList<String>();
        while (m.find(matcher_start)){
            ex_urls.add(m.group(1).replaceAll("\"","").replaceAll("'","").replaceAll("\n","").replaceAll("\t","").trim());
            matcher_start = m.end();
        }
        LinkedHashSet<String> hashSet = new LinkedHashSet<>(ex_urls);
        ArrayList<String> temp_urls = new ArrayList<>(hashSet);
        List<String> all_urls = new ArrayList<>();
        for(String temp_url:temp_urls){
            all_urls.add(process_url(url, temp_url));
        }
        List<String> result = new ArrayList<String>();
        for(String singerurl:all_urls){
            String domain = url.getHost();
            try {
                URL subURL = new URL(singerurl);
                String subdomain = subURL.getHost();
                if(!subdomain.equalsIgnoreCase(domain) && !isStaticFile(singerurl) && !singerurl.endsWith(".js") && !singerurl.contains(".js?") && !isWhiteDomain(singerurl) && !BurpExtender.hasScanDomainSet.contains(Utils.getUriFromUrl(singerurl))){
                    BurpExtender.hasScanDomainSet.add(Utils.getUriFromUrl(singerurl));
                    result.add(singerurl);
                    }

            } catch (Exception e) {
            }

        }
        return  result;
    }

    public static String process_url(URL url, String re_URL) {
        String black_url = "javascript:";
        String ab_URL = url.getHost() + ":"+ url.getPort();
        String host_URL = url.getProtocol();
        String result = "";
        if (re_URL.length() < 4) {
            if (re_URL.startsWith("//")) {
                result = host_URL + ":" + "//" + ab_URL + re_URL.substring(1);
            } else if (!re_URL.startsWith("//")) {
                if (re_URL.startsWith("/")) {
                    result = host_URL + "://" + ab_URL + re_URL;
                } else {
                    if (re_URL.startsWith(".")) {
                        if (re_URL.startsWith("..")) {
                            result = host_URL + "://" + ab_URL + re_URL.substring(2);
                        } else {
                            result = host_URL + "://" + ab_URL + re_URL.substring(1);
                        }
                    } else {
                        result = host_URL + "://" + ab_URL + "/" + re_URL;
                    }

                }

            }
        } else {
            if (re_URL.startsWith("//")) {
                result = host_URL + ":" + re_URL;
            } else if (re_URL.startsWith("http")) {
                result = re_URL;
            } else if (!re_URL.startsWith("//") && !re_URL.contains(black_url)) {
                if (re_URL.startsWith("/")) {
                    result = host_URL + "://" + ab_URL + re_URL;
                } else {
                    if (re_URL.startsWith(".")) {
                        if (re_URL.startsWith("..")) {
                            result = host_URL + "://" + ab_URL + re_URL.substring(2);
                        } else {
                            result = host_URL + "://" + ab_URL + re_URL.substring(1);
                        }
                    } else {
                        result = host_URL + "://" + ab_URL + "/" + re_URL;
                    }

                }

            } else {
                result = url.toString();
            }
        }
        return result;

    }

    public static List<Integer> find_last(String string, String str)
    {
        List<Integer> positions = new ArrayList<Integer>();
        int last_position= -1;
        while(true){
            int position = string.lastIndexOf(str,last_position+1);
            if(position == -1){
                break;
            }
            last_position = position;
            positions.add(position);
        }


        return positions;
    }

    public static List<String> extractUrlsFromHtml(String uri, String html) {
        // 使用正则表达式提取文本内容中的 URL
        List<String> urlList = new ArrayList<String>();
        Pattern pattern = Pattern.compile(
                "(http|https|ftp)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?");
        Matcher matcher = pattern.matcher(html);
        while (matcher.find()) {
            String url = matcher.group();
            if (!url.contains("http") && url.startsWith("/")) {
                try {
                    URI baseUri = new URI(uri);
                    url = baseUri.resolve(url).toString();
                } catch (URISyntaxException e) {
                    continue;
                }
            }
            try{
                String subdomain = (new URL(uri)).getHost() + ":" + (new URL(uri)).getPort();
                String domain = (new URL(url)).getHost() + ":" + (new URL(uri)).getPort();
                if (subdomain.equalsIgnoreCase(domain)){
                    continue;
                }
            } catch (Exception e) {
                continue;
            }

            if (!isStaticFile(url) && !url.endsWith(".js") && !url.contains(".js?") && !isWhiteDomain(url) && !BurpExtender.hasScanDomainSet.contains(Utils.getUriFromUrl(url))){
                BurpExtender.hasScanDomainSet.add(Utils.getUriFromUrl(url));
                urlList.add(url);
            }
        }
        return urlList;
    }

    public static void trustAllCertificates() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(
                            X509Certificate[] certs, String authType) {
                    }
                    public void checkServerTrusted(
                            X509Certificate[] certs, String authType) {
                    }
                }
        };

        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        // Create all-trusting host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };

        // Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
    }



    /**
     * 获取-插件运行路径
     *
     * @return
     */
    public static String getExtensionFilePath(IBurpExtenderCallbacks callbacks) {
        String path = "";
        Integer lastIndex = callbacks.getExtensionFilename().lastIndexOf(File.separator);
        path = callbacks.getExtensionFilename().substring(0, lastIndex) + File.separator;
        return path;
    }

    public static IHttpService iHttpService(String host, int port, String protocol){
        return new IHttpService() {
            @Override
            public String getHost() {
                return host;
            }

            @Override
            public int getPort() {
                return port;
            }

            @Override
            public String getProtocol() {
                return protocol;
            }
        };
    }

    public static String escapeCsv(String value) {
        String escapedValue = value;
        if (value.contains("\"")) {
            // 将所有的双引号替换成两个双引号
            escapedValue = escapedValue.replace("\"", "\"\"");
        }
        // 如果值包含逗号、双引号或换行符，将其包围在双引号之中
        if (value.contains(",") || value.contains("\n") || value.contains("\"")) {
            escapedValue = "\"" + escapedValue + "\"";
        }
        return escapedValue;
    }

}

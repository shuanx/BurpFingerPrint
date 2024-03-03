package burp.util;

import burp.BurpExtender;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import burp.ui.LogEntry;
import org.apache.commons.codec.binary.Base64;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import javax.net.ssl.HttpsURLConnection;
import org.apache.commons.codec.digest.MurmurHash3;
import org.apache.commons.io.IOUtils;


/**
 * @author： shaun
 * @create： 2024/2/18 21:11
 * @description：TODO
 */
public class Utils {
    public final static String[] STATIC_FILE_EXT = new String[]{
            "png",
            "jpg",
            "jpeg",
            "gif",
            "pdf",
            "bmp",
            "js",
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
            "xls",
            "xlsx",
            "doc",
            "docx",
            "ppt",
            "pptx",
            "iso"
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

    public static String getUriExt(String url) {
        String pureUrl = url.substring(0, url.contains("?") ? url.indexOf("?") : url.length());
        return (pureUrl.lastIndexOf(".") > -1 ? pureUrl.substring(pureUrl.lastIndexOf(".") + 1) : "").toLowerCase();
    }

    public static boolean urlExistsInLog(List<LogEntry> log, String url) {
        for (LogEntry logEntry : log) {
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
            return matcher.group(1);
        }
        else{
            return urlString;
        }
    }
    public static String getFaviconHash(String siteUrl) throws Exception {
        InputStream faviconStream = getFaviconStream(siteUrl);
        byte[] faviconBytes = IOUtils.toByteArray(faviconStream);
        faviconStream.close();

        byte[] base64Bytes = java.util.Base64.getEncoder().encode(faviconBytes);
        return murmur3Hash32(base64Bytes);
    }

    public static InputStream getFaviconStream(String siteUrl) throws Exception {
        URL url = new URL(siteUrl);
        URLConnection connection;
        if (siteUrl.startsWith("https")) {
            connection = (HttpsURLConnection) url.openConnection();
        } else {
            connection = (HttpURLConnection) url.openConnection();
        }
        return connection.getInputStream();
    }

    public static String murmur3Hash32(byte[] base64Bytes) {
        int hash = MurmurHash3.hash32x86(base64Bytes);
        return String.valueOf(hash);
    }
}

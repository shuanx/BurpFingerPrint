package burp.ui;

import java.awt.*;
import java.util.HashMap;
import javax.swing.*;

import burp.ITab;
import burp.IBurpExtenderCallbacks;
import burp.model.FingerPrintRule;


public class Tags implements ITab {

    private final JTabbedPane tabs;
    private String tagName;
    private FingerTab fingerTab = new FingerTab();
    public FingerConfigTab fingerConfigTab = new FingerConfigTab();

    public Tags(IBurpExtenderCallbacks callbacks, String name){

        this.tagName = name;
        // 定义tab标签页
        tabs = new JTabbedPane();
        tabs.add("指纹识别", fingerTab.contentPane);
        tabs.add("指纹配置", fingerConfigTab);

        // 修改选中的标签页名字颜色

        // 将整个tab加载到平台即可
        callbacks.customizeUiComponent(tabs);
        // 将自定义选项卡添加到Burp的UI
        callbacks.addSuiteTab(Tags.this);

    }


    @Override
    public String getTabCaption() {
        return this.tagName;
    }

    @Override
    public Component getUiComponent() {
        return this.tabs;
    }
}
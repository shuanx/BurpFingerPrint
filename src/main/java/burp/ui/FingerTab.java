package burp.ui;

import burp.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashSet;
import java.util.HashMap;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.event.TableModelListener;
import javax.swing.event.TableModelEvent;
import java.util.Collections;
import java.util.LinkedList;
import java.util.Map;
import java.util.TreeMap;


public class FingerTab implements IMessageEditorController {
    public static JPanel contentPane;
    private JLabel lbHost;
    private JTextField tfHost;
    private JLabel lbPort;
    private JTextField tfPort;
    private JLabel lbTimeout;
    private JTextField tfTimeout;
    private JLabel lbIntervalTime;
    private JTextField tfIntervalTime;
    private JLabel lbUsername;
    private JTextField tfUsername;
    private JLabel lbPassword;
    private JTextField tfPassword;
    private JTextField tfDomain;
    private JTextField tfExcludeSuffix;
    private JTextField tfBlackList;
    private JToggleButton btnConn;
    private JButton btnClear;
    private JSplitPane splitPane;
    public static HttpLogTable logTable;
    public static IHttpRequestResponse currentlyDisplayedItem;
    public static JLabel lbRequestCount;
    public static JLabel lbSuccessCount;
    public static JLabel lbFailCount;

    public static IMessageEditor requestViewer;
    public static IMessageEditor responseViewer;
    public static ITextEditor resultDeViewer;

    public static HashMap<String, JLabel> resultMap = new HashMap<>();
    public static JPanel tagsPanel;

    // 菜单页面
    public static JMenuBar menuBar;
    public static JMenu menuMainPage;
    public static JMenu menuConfigPage;


    public FingerTab() {
        contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        contentPane.setLayout(new BorderLayout(0, 0));

        JPanel topPanel = new JPanel();
        GridBagLayout gridBagLayout = new GridBagLayout();
        // 列数，行数
        gridBagLayout.columnWidths = new int[] { 0, 0};
        gridBagLayout.rowHeights = new int[] {5};
        // 各列占宽度比，各行占高度比
        gridBagLayout.columnWeights = new double[] { 1.0D, Double.MIN_VALUE };
        topPanel.setLayout(gridBagLayout);

        JPanel FilterPanel = new JPanel();
        GridBagConstraints gbc_panel_1 = new GridBagConstraints();
        gbc_panel_1.insets = new Insets(0, 5, 5, 5);
        gbc_panel_1.fill = 2;
        gbc_panel_1.gridx = 0;
        gbc_panel_1.gridy = 2;
        topPanel.add(FilterPanel, gbc_panel_1);
        GridBagLayout gbl_panel_1 = new GridBagLayout();
        gbl_panel_1.columnWidths = new int[] { 0, 0, 0, 0, 0 };
        gbl_panel_1.rowHeights = new int[] { 0, 0 };
        gbl_panel_1.columnWeights = new double[] { 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, Double.MIN_VALUE};
        gbl_panel_1.rowWeights = new double[] { 0.0D, Double.MIN_VALUE };
        FilterPanel.setLayout(gbl_panel_1);

        // 在添加 "Requests Total" 和 lbRequestCount 之前添加一个占位组件
        Component leftStrut = Box.createHorizontalStrut(5); // 你可以根据需要调整这个值
        GridBagConstraints gbc_leftStrut = new GridBagConstraints();
        gbc_leftStrut.insets = new Insets(0, 0, 0, 5);
        gbc_leftStrut.fill = GridBagConstraints.HORIZONTAL;
        gbc_leftStrut.weightx = 1.0; // 这个值决定了 leftStrut 占据的空间大小
        gbc_leftStrut.gridx = 10;
        gbc_leftStrut.gridy = 0;
        FilterPanel.add(leftStrut, gbc_leftStrut);

        // 转发url总数，默认0
        JLabel lbRequest = new JLabel("Requests Total:");
        GridBagConstraints gbc_lbRequest = new GridBagConstraints();
        gbc_lbRequest.insets = new Insets(0, 0, 0, 5);
        gbc_lbRequest.fill = GridBagConstraints.HORIZONTAL;
        gbc_lbRequest.weightx = 0.0;
        gbc_lbRequest.gridx = 0;
        gbc_lbRequest.gridy = 0;
        FilterPanel.add(lbRequest, gbc_lbRequest);

        lbRequestCount = new JLabel("0");
        lbRequestCount.setForeground(new Color(0,0,255));
        GridBagConstraints gbc_lbRequestCount = new GridBagConstraints();
        gbc_lbRequestCount.insets = new Insets(0, 0, 0, 5);
        gbc_lbRequest.fill = GridBagConstraints.HORIZONTAL;
        gbc_lbRequest.weightx = 0.0;
        gbc_lbRequestCount.gridx = 1;
        gbc_lbRequestCount.gridy = 0;
        FilterPanel.add(lbRequestCount, gbc_lbRequestCount);

        // 转发成功url数，默认0
        JLabel lbSucces = new JLabel("Finger Success:");
        GridBagConstraints gbc_lbSucces = new GridBagConstraints();
        gbc_lbSucces.insets = new Insets(0, 0, 0, 5);
        gbc_lbSucces.fill = 0;
        gbc_lbSucces.gridx = 2;
        gbc_lbSucces.gridy = 0;
        FilterPanel.add(lbSucces, gbc_lbSucces);

        lbSuccessCount = new JLabel("0");
        lbSuccessCount.setForeground(new Color(0, 255, 0));
        GridBagConstraints gbc_lbSuccessCount = new GridBagConstraints();
        gbc_lbSuccessCount.insets = new Insets(0, 0, 0, 5);
        gbc_lbSuccessCount.fill = 0;
        gbc_lbSuccessCount.gridx = 3;
        gbc_lbSuccessCount.gridy = 0;
        FilterPanel.add(lbSuccessCount, gbc_lbSuccessCount);

        // 添加一个 "清除" 按钮
        JButton btnClear = new JButton("清除");
        GridBagConstraints gbc_btnClear = new GridBagConstraints();
        gbc_btnClear.insets = new Insets(0, 0, 0, 5);
        gbc_btnClear.fill = 0;
        gbc_btnClear.gridx = 11;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnClear.gridy = 0;
        FilterPanel.add(btnClear, gbc_btnClear);

        contentPane.add(topPanel,BorderLayout.NORTH);

        tagsPanel = new JPanel();
        tagsPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        GridBagConstraints gbc_tagsPanel = new GridBagConstraints();
        gbc_tagsPanel.insets = new Insets(0, 0, 5, 0);
        gbc_tagsPanel.fill = GridBagConstraints.HORIZONTAL;
        gbc_tagsPanel.gridx = 0;
        gbc_tagsPanel.gridy = 1;  // 新的行
        topPanel.add(tagsPanel, gbc_tagsPanel);

        JLabel allLabel = new JLabel("全部");
        allLabel.setOpaque(true);  // 设置为不透明
        allLabel.setBackground(new Color(200, 200, 200));  // 设置背景颜色为浅灰色
        allLabel.setForeground(Color.BLACK);  // 设置字体颜色为黑色

        // 为标签添加一个有颜色的边框，边框内有5像素的填充
        allLabel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(100, 100, 100), 1),  // 外部边框，颜色为深灰色，宽度为2像素
                BorderFactory.createEmptyBorder(5, 5, 5, 5)  // 内部填充，宽度为5像素
        ));
        allLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                // 当用户点击 "全部"，展示所有的数据
                ((TableRowSorter<TableModel>)logTable.getRowSorter()).setRowFilter(null);
            }
        });
        tagsPanel.add(allLabel);

        contentPane.add(topPanel,BorderLayout.NORTH);  // 只在 contentPane 的北部添加一个组件

        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setDividerLocation(0.5);
        contentPane.add(splitPane, BorderLayout.CENTER);

        HttpLogTableModel model = new HttpLogTableModel();
        logTable = new HttpLogTable(model);
        logTable.setAutoCreateRowSorter(true);  // 添加这一行来启用自动创建行排序器
        logTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        logTable.setRowSelectionAllowed(true);

        model.addTableModelListener(new TableModelListener() {
            @Override
            public void tableChanged(TableModelEvent e) {
                HashMap<String, Integer> resultCounts = new HashMap<>();
                // 遍历表格中所有行
                for(int i = 0; i < model.getRowCount(); i++) {
                    String result = (String) model.getValueAt(i, 5); // 获取结果值
                    String[] parts = result.split(", "); // 根据", "进行切分
                    for(String part : parts) {
                        resultCounts.put(part, resultCounts.getOrDefault(part, 0) + 1); // 添加到映射中进行去重，并计数
                    }
                }
                clearAllResultLabels();

                // 创建一个 TreeMap 并进行反向排序
                TreeMap<Integer, LinkedList<String>> sortedResults = new TreeMap<>(Collections.reverseOrder());
                for(Map.Entry<String, Integer> entry : resultCounts.entrySet()) {
                    sortedResults.computeIfAbsent(entry.getValue(), k -> new LinkedList<>()).add(entry.getKey());
                }

                // 添加新的结果标签
                for(Map.Entry<Integer, LinkedList<String>> entry : sortedResults.entrySet()) {
                    Integer count = entry.getKey();
                    for(String result : entry.getValue()) {
                        FingerTab.addNewResultLabel(result + " (" + count + ")", model);
                    }
                }
            }
        });


        // 创建右键菜单
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem clearItem = new JMenuItem("清除");
        popupMenu.add(clearItem);
        // 将右键菜单添加到表格
        logTable.setComponentPopupMenu(popupMenu);

        // 为菜单项添加行为
        clearItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int successRequestsCount = Integer.parseInt(lbSuccessCount.getText()) - logTable.getSelectedRows().length;
                lbSuccessCount.setText(Integer.toString(successRequestsCount));
                model.removeSelectedRows(logTable);
            }
        });

        JScrollPane jspLogTable = new JScrollPane(logTable);
        splitPane.setTopComponent(jspLogTable);

        // 添加点击事件监听器
        btnClear.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清除表格数据
                lbRequestCount.setText("0");
                lbSuccessCount.setText("0");
                model.setRowCount();
                BurpExtender.hasScanDomainSet = new HashSet<>();
                clearAllResultLabels();
            }
        });


        JTabbedPane tabs = new JTabbedPane();
        requestViewer = BurpExtender.callbacks.createMessageEditor(this, false);
        responseViewer = BurpExtender.callbacks.createMessageEditor(this, false);
        resultDeViewer = BurpExtender.callbacks.createTextEditor();

        tabs.addTab("Result Details", resultDeViewer.getComponent());
        tabs.addTab("Request", requestViewer.getComponent());
        tabs.addTab("Original Response", responseViewer.getComponent());
        splitPane.setBottomComponent(tabs);

        BurpExtender.callbacks.customizeUiComponent(topPanel);
    }

    public Component getComponet(){
        return contentPane;
    }

    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    public static void addNewResultLabel(String result, HttpLogTableModel model) {
        // 创建新的标签
        JLabel newLabel = new JLabel(result);
        newLabel.setOpaque(true);  // 设置为不透明
        newLabel.setBackground(new Color(200, 200, 200));  // 设置背景颜色为浅灰色
        newLabel.setForeground(Color.BLACK);  // 设置字体颜色为黑色

        // 为标签添加一个有颜色的边框，边框内有5像素的填充
        newLabel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(100, 100, 100), 1),  // 外部边框，颜色为深灰色，宽度为2像素
                BorderFactory.createEmptyBorder(5, 5, 5, 5)  // 内部填充，宽度为5像素
        ));

        newLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                // 当用户点击某个标签时，展示所有包含该标签文本的结果
                String filterWithoutCount = result.replaceAll("\\(.*\\)", "").trim();
                ((TableRowSorter<TableModel>)logTable.getRowSorter())
                        .setRowFilter(RowFilter.regexFilter(filterWithoutCount, 5));
            }
        });

        // 添加新的标签到面板和 resultMap
        tagsPanel.add(newLabel);
        resultMap.put(result, newLabel);
        // 重新验证和重绘面板
        tagsPanel.revalidate();
        tagsPanel.repaint();
    }

    public void clearAllResultLabels() {
        for (Component component : tagsPanel.getComponents()) {
            if (component instanceof JLabel) {
                JLabel label = (JLabel) component;
                // 如果标签的文本不是"全部"，则移除
                if (!"全部".equals(label.getText())) {
                    tagsPanel.remove(component);
                }
            }
        }
        tagsPanel.revalidate();
        tagsPanel.repaint();
    }



}


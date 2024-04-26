package burp.ui;

import burp.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.sql.SQLException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.table.*;
import java.awt.Component;
import java.util.Map;
import java.util.ArrayList;

//import burp.ui.event.FingerTabEventHandlers;
import burp.model.DatabaseService;
import burp.model.TableLogModel;
import burp.ui.event.FingerTabEventHandlers;
import burp.ui.renderer.CenterTableCellRenderer;
import burp.ui.renderer.HavingImportantRenderer;
import burp.ui.renderer.HeaderIconRenderer;
import burp.ui.renderer.IconTableCellRenderer;
import burp.util.UiUtils;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.ListSelectionEvent;


public class FingerTab implements IMessageEditorController {
    public static JPanel contentPane;
    private JSplitPane splitPane;
    public static IHttpRequestResponse currentlyDisplayedItem;
    public static JLabel lbRequestCount;
    public static JLabel lbSuccessCount;

    public static IMessageEditor requestViewer;
    public static IMessageEditor responseViewer;
    public static ITextEditor resultDeViewer;

    public static HashMap<String, JLabel> resultMap = new HashMap<>();
    public static JPanel tagsPanel;

    // 在FingerTab类中添加成员变量
    public static JToggleButton toggleButton;
    private static DefaultTableModel model;
    public static JTable table;
    public static JToggleButton flashButton;
    public static JComboBox<String> choicesComboBox;
    public static JLabel flashText;
    public static Timer timer;
    public static LocalDateTime operationStartTime = LocalDateTime.now();
    public static String historyChoiceType = "全部";
    public static String historyChoiceJMenuItem = "全部";
    public static JLabel currentSelectedLabel = null;

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

        toggleButton = new JToggleButton(UiUtils.getImageIcon("/icon/openButtonIcon.png", 40, 24));
        toggleButton.setSelectedIcon(UiUtils.getImageIcon("/icon/shutdownButtonIcon.png", 40, 24));
        toggleButton.setPreferredSize(new Dimension(50, 24));
        toggleButton.setBorder(null);  // 设置无边框
        toggleButton.setFocusPainted(false);  // 移除焦点边框
        toggleButton.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        toggleButton.setToolTipText("指纹识别功能开");

        // 添加填充以在左侧占位
        GridBagConstraints gbc_leftFiller = new GridBagConstraints();
        gbc_leftFiller.weightx = 1; // 使得这个组件吸收额外的水平空间
        gbc_leftFiller.gridx = 5; // 位置设置为第一个单元格
        gbc_leftFiller.gridy = 0; // 第一行
        gbc_leftFiller.fill = GridBagConstraints.HORIZONTAL; // 水平填充
        FilterPanel.add(Box.createHorizontalGlue(), gbc_leftFiller);

        // 设置按钮的 GridBagConstraints
        GridBagConstraints gbc_buttons = new GridBagConstraints();
        gbc_buttons.insets = new Insets(0, 5, 0, 5);
        gbc_buttons.gridy = 0; // 设置按钮的纵坐标位置
        gbc_buttons.fill = GridBagConstraints.NONE; // 不填充
        gbc_buttons.gridx = 7; // 将横坐标位置移动到下一个单元格
        FilterPanel.add(toggleButton, gbc_buttons);

        // 刷新按钮按钮
        flashButton = new JToggleButton(UiUtils.getImageIcon("/icon/runningButton.png", 24, 24));
        flashButton.setSelectedIcon(UiUtils.getImageIcon("/icon/flashButton.png", 24, 24));
        flashButton.setPreferredSize(new Dimension(30, 30));
        flashButton.setBorder(null);  // 设置无边框
        flashButton.setFocusPainted(false);  // 移除焦点边框
        flashButton.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        flashButton.setToolTipText("用于控制表格是否自动化刷新，还是手工点击刷新");


        // 刷新按钮
        flashButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 检查按钮的选中状态
                if (flashButton.isSelected()) {
                    // 如果按钮被选中，意味着刷新功能被激活，我们将文本设置为 "暂停刷新中"
                    flashText.setText("暂停每5秒刷新表格");
                } else {
                    // 如果按钮没有被选中，意味着刷新功能没有被激活，我们将文本设置为 "自动刷新"
                    flashText.setText("自动每5秒刷新表格中");
                }
            }
        });

        // 刷新文本
        flashText = new JLabel("自动每5秒刷新表格中");

        gbc_buttons.gridx = 8; // 将横坐标位置移动到下一个单元格
        FilterPanel.add(flashButton, gbc_buttons);
        gbc_buttons.gridx = 9; // 将横坐标位置移动到下一个单元格
        FilterPanel.add(flashText, gbc_buttons);

        // 添加填充以在右侧占位
        GridBagConstraints gbc_rightFiller = new GridBagConstraints();
        gbc_rightFiller.weightx = 1; // 使得这个组件吸收额外的水平空间
        gbc_rightFiller.gridx = 11; // 位置设置为最后一个单元格
        gbc_rightFiller.gridy = 0; // 第一行
        gbc_rightFiller.fill = GridBagConstraints.HORIZONTAL; // 水平填充
        FilterPanel.add(Box.createHorizontalGlue(), gbc_rightFiller);

        // 在FingerTab类中添加事件监听器
//        allFingerprintsButton.addActionListener(FingerTabEventHandlers.allFingerprintsButtonAddActionListener(logTable, allFingerprintsButton));

        toggleButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 例如，更新FingerConfigTab中的按钮状态
                BurpExtender.getTags().fingerConfigTab.toggleButton.setSelected(toggleButton.isSelected());
            }
        });

        // 添加一个 "清除" 按钮
        JButton btnClear = new JButton("清空");
        GridBagConstraints gbc_btnClear = new GridBagConstraints();
        gbc_btnClear.insets = new Insets(0, 0, 0, 5);
        gbc_btnClear.fill = 0;
        gbc_btnClear.gridx = 13;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnClear.gridy = 0;
        FilterPanel.add(btnClear, gbc_btnClear);

        // 功能按钮
        JPopupMenu moreMenu = new JPopupMenu("功能");
        JMenuItem exportItem = new JMenuItem("导出");
        moreMenu.add(exportItem);
        exportItem.setIcon(UiUtils.getImageIcon("/icon/exportItem.png", 17, 17));
        moreMenu.add(exportItem);
        JButton moreButton = new JButton();
        moreButton.setIcon(UiUtils.getImageIcon("/icon/moreButton.png", 17, 17));
        GridBagConstraints gbc_btnMore = new GridBagConstraints();
        gbc_btnClear.insets = new Insets(0, 0, 0, 5);
        gbc_btnClear.fill = 0;
        gbc_btnClear.gridx = 14;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnClear.gridy = 0;
        FilterPanel.add(moreButton, gbc_btnMore);

//        exportItem.addActionListener(FingerTabEventHandlers.exportItemAddActionListener(contentPane, logTable));

        // 点击”功能“的监听事件
        moreButton.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                moreMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        });

        contentPane.add(topPanel,BorderLayout.NORTH);

        tagsPanel = new JPanel();
        tagsPanel.setLayout(new WrapLayout(FlowLayout.LEFT)); // 使用 WrapLayout 并设置为左对齐
        GridBagConstraints gbc_tagsPanel = new GridBagConstraints();
        gbc_tagsPanel.insets = new Insets(0, 0, 5, 0);
        gbc_tagsPanel.fill = GridBagConstraints.HORIZONTAL;
        gbc_tagsPanel.gridx = 0;
        gbc_tagsPanel.gridy = 1;  // 新的行
        topPanel.add(tagsPanel, gbc_tagsPanel);

        JLabel allLabel = new JLabel("全部");
        allLabel.setOpaque(true);  // 设置为不透明
        allLabel.setBackground(new Color(150, 150, 150));  // 设置背景颜色为浅灰色
        allLabel.setForeground(Color.BLACK);  // 设置字体颜色为黑色
        FingerTab.currentSelectedLabel = allLabel;
        // 为标签添加一个有颜色的边框，边框内有5像素的填充
        allLabel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(100, 100, 100), 1),  // 外部边框，颜色为深灰色，宽度为2像素
                BorderFactory.createEmptyBorder(5, 5, 5, 5)  // 内部填充，宽度为5像素
        ));
        allLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                // 取消之前选中标签的颜色
                if (FingerTab.currentSelectedLabel != null) {
                    FingerTab.currentSelectedLabel.setBackground(new Color(200, 200, 200)); // 还原默认背景色
                }
                setFlashButtonTrue();
                // 设置当前点击的标签为选中状态
                allLabel.setBackground(new Color(150, 150, 150)); // 选中状态的背景色
                FingerTab.currentSelectedLabel = allLabel; // 更新当前选中的标签
                // 当用户点击 "全部"，展示所有的数据
                historyChoiceType = "全部";
                historyChoiceJMenuItem = "全部";
                filterTable("全部", "全部", null);
            }
        });
        tagsPanel.add(allLabel);

        contentPane.add(topPanel,BorderLayout.NORTH);  // 只在 contentPane 的北部添加一个组件

        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setDividerLocation(0.5);
        contentPane.add(splitPane, BorderLayout.CENTER);

        // 数据展示面板
        model = new DefaultTableModel(new Object[]{"#", "Method", "URl", "Titled", "Status", "Result", "type", "isImportant", "Time"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                // This will make all cells of the table non-editable
                return false;
            }
        };
        table = new JTable(model){
            // 重写getToolTipText方法以返回特定单元格的数据
            public String getToolTipText(MouseEvent e) {
                int row = rowAtPoint(e.getPoint());
                int col = columnAtPoint(e.getPoint());
                if (row > -1 && col > -1) {
                    Object value = getValueAt(row, col);
                    return value == null ? null : value.toString();
                }
                return super.getToolTipText(e);
            }
        };;


        // 前两列设置宽度 30px、60px
        table.getColumnModel().getColumn(0).setMinWidth(20);
        table.getColumnModel().getColumn(1).setMinWidth(20);
        table.getColumnModel().getColumn(2).setMinWidth(200);
        table.getColumnModel().getColumn(3).setMinWidth(60);
        table.getColumnModel().getColumn(4).setMinWidth(20);
        table.getColumnModel().getColumn(5).setMinWidth(180);
        table.getColumnModel().getColumn(6).setMinWidth(180);
        table.getColumnModel().getColumn(7).setMinWidth(20);
        table.getColumnModel().getColumn(8).setMinWidth(60);

        // 创建一个居中对齐的单元格渲染器
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);

        DefaultTableCellRenderer leftRenderer = new DefaultTableCellRenderer();
        leftRenderer.setHorizontalAlignment(JLabel.LEFT);

        table.getColumnModel().getColumn(0).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(1).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(2).setCellRenderer(leftRenderer);
        table.getColumnModel().getColumn(3).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(5).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(6).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(7).setCellRenderer(leftRenderer);
        table.getColumnModel().getColumn(8).setCellRenderer(leftRenderer);

        HavingImportantRenderer havingImportantRenderer = new HavingImportantRenderer();
        table.getColumnModel().getColumn(7).setCellRenderer(havingImportantRenderer);

        // 在FingerConfigTab构造函数中设置表头渲染器和监听器的代码
        JTableHeader header = table.getTableHeader();
        TableColumnModel columnModel = header.getColumnModel();
        columnModel.getColumn(6).setHeaderRenderer(new HeaderIconRenderer());
        columnModel.getColumn(7).setHeaderRenderer(new HeaderIconRenderer());

        // 在您的FingerConfigTab构造函数中
        header.addMouseListener(FingerTabEventHandlers.headerAddMouseListener(table));

        model.addTableModelListener(FingerTabEventHandlers.modelAddTableModelListener(model, tagsPanel, resultMap, table));

        // 创建右键菜单
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem clearItem = new JMenuItem("清除");
        popupMenu.add(clearItem);
        // 将右键菜单添加到表格
        table.setComponentPopupMenu(popupMenu);

        // 为菜单项添加行为
        clearItem.addActionListener(FingerTabEventHandlers.clearItemAddActionListener(model, table, lbSuccessCount));

        JScrollPane jspLogTable = new JScrollPane(table);
        splitPane.setTopComponent(jspLogTable);

        // 设置表格选择模式为单行选择
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // 添加ListSelectionListener来监听行选择事件
        table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
                                                               public void valueChanged(ListSelectionEvent event) {
                                                                   if (!event.getValueIsAdjusting() && table.getSelectedRow() != -1) {
                                                                       // 在这里获取选中行的数据
                                                                       int selectedRow = table.getSelectedRow();

                                                                       // 根据您的数据模型结构获取数据
                                                                       String url = model.getValueAt(selectedRow, 2).toString();
                                                                       TableLogModel logModel = BurpExtender.getDataBaseService().getTableDataByUrl(url);
                                                                       resultDeViewer.setText(logModel.getResultInfo().getBytes());
                                                                       Map<String, byte[]> requestResponse = BurpExtender.getDataBaseService().selectRequestResponseById(logModel.getRequestResponseIndex());

                                                                       if (requestResponse != null) {
                                                                           // 提取请求和响应数据
                                                                           byte[] requestBytes = requestResponse.get("request");
                                                                           byte[] responseBytes = requestResponse.get("response");

                                                                           // 现在你可以使用这些字节数据了
                                                                           // 例如，你可以将它们设置到一个 HTTP 消息编辑器组件中
                                                                           requestViewer.setMessage(requestBytes, true); // true 表示请求消息
                                                                           responseViewer.setMessage(responseBytes, false); // false 表示响应消息
                                                                       }

                                                                   }
                                                               }
                                                           });

        // 添加点击事件监听器
        btnClear.addActionListener(FingerTabEventHandlers.btnClearAddActionListener(model, lbRequestCount, lbSuccessCount));


        JTabbedPane tabs = new JTabbedPane();
        requestViewer = BurpExtender.getCallbacks().createMessageEditor(this, false);
        responseViewer = BurpExtender.getCallbacks().createMessageEditor(this, false);
        resultDeViewer = BurpExtender.getCallbacks().createTextEditor();

        tabs.addTab("Result Details", resultDeViewer.getComponent());
        tabs.addTab("Request", requestViewer.getComponent());
        tabs.addTab("Original Response", responseViewer.getComponent());
        splitPane.setBottomComponent(tabs);

        BurpExtender.getCallbacks().customizeUiComponent(topPanel);

        // 构建一个定时刷新页面函数
        // 创建一个每5秒触发一次的定时器
        int delay = 5000; // 延迟时间，单位为毫秒
        timer = new Timer(delay, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 调用刷新表格的方法
                try{
                    refreshTableModel();
                } catch (Exception ep){
                    BurpExtender.getStderr().println("[!] 刷新表格报错， 报错如下：");
                    ep.printStackTrace(BurpExtender.getStderr());
                }
            }
        });

        timer.start();



    }

    public static void refreshTableModel(){
        // 刷新页面, 如果自动更新关闭，则不刷新页面内容
        // lbSuccessCount.setText(String.valueOf(BurpExtender.getDataBaseService().getApiDataCount()));
        if(getFlashButtonStatus()){
            if (Duration.between(operationStartTime, LocalDateTime.now()).getSeconds() > 600){
                setFlashButtonTrue();
            }
            return;
        }
        // 设置所有状态码为关闭
        showFilter();
    }


    public static void showFilter(){
        synchronized (model) {
            // 清空model后，根据URL来做匹配
            model.setRowCount(0);
            lbSuccessCount.setText(Integer.toString(BurpExtender.getDataBaseService().getTableDataCount()));
            // 获取数据库中的所有ApiDataModels
            java.util.List<TableLogModel> allApiDataModels = BurpExtender.getDataBaseService().getAllTableDataModels();

            // 遍历apiDataModelMap
            for (TableLogModel apiDataModel : allApiDataModels) {
                model.insertRow(0, new Object[]{
                        apiDataModel.getPid(),
                        apiDataModel.getMethod(),
                        apiDataModel.getUrl(),
                        apiDataModel.getTitle(),
                        apiDataModel.getStatus(),
                        apiDataModel.getResult(),
                        apiDataModel.getType(),
                        apiDataModel.getIsImportant(),
                        apiDataModel.getTime()
                });
            }
        }
    }

    public static void filterTable(String typeFilter, String resultFilter, Boolean isImportantFilter) {
        try{
            // 清空model后，根据URL来做匹配
            model.setRowCount(0);
            lbSuccessCount.setText(Integer.toString(BurpExtender.getDataBaseService().getTableDataCount()));
            java.util.List<TableLogModel> allApiDataModels;
            // 获取数据库中的所有ApiDataModels
            allApiDataModels = BurpExtender.getDataBaseService().getTableDataModelsByFilter(typeFilter, resultFilter, isImportantFilter);
            operationStartTime = LocalDateTime.now();
            // 遍历apiDataModelMap
            for (TableLogModel apiDataModel : allApiDataModels) {
                model.insertRow(0, new Object[]{
                        apiDataModel.getPid(),
                        apiDataModel.getMethod(),
                        apiDataModel.getUrl(),
                        apiDataModel.getTitle(),
                        apiDataModel.getStatus(),
                        apiDataModel.getResult(),
                        apiDataModel.getType(),
                        apiDataModel.getIsImportant(),
                        apiDataModel.getTime()
                });
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error filterTableByType: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
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

    public class WrapLayout extends FlowLayout {
        public WrapLayout() {
            super();
        }

        public WrapLayout(int align) {
            super(align);
        }

        public WrapLayout(int align, int hgap, int vgap) {
            super(align, hgap, vgap);
        }

        @Override
        public Dimension preferredLayoutSize(Container target) {
            return layoutSize(target, true);
        }

        @Override
        public Dimension minimumLayoutSize(Container target) {
            Dimension minimum = layoutSize(target, false);
            minimum.width -= (getHgap() + 1);
            return minimum;
        }

        private Dimension layoutSize(Container target, boolean preferred) {
            synchronized (target.getTreeLock()) {
                int targetWidth = target.getSize().width;
                Container container = target;

                while (container.getSize().width == 0 && container.getParent() != null) {
                    container = container.getParent();
                }

                targetWidth = container.getSize().width;

                if (targetWidth == 0) {
                    targetWidth = Integer.MAX_VALUE;
                }

                int hgap = getHgap();
                int vgap = getVgap();
                Insets insets = target.getInsets();
                int horizontalInsetsAndGap = insets.left + insets.right + (hgap * 2);
                int maxWidth = targetWidth - horizontalInsetsAndGap;

                // Fit components into the allowed width
                Dimension dim = new Dimension(0, 0);
                int rowWidth = 0;
                int rowHeight = 0;

                int nmembers = target.getComponentCount();

                for (int i = 0; i < nmembers; i++) {
                    Component m = target.getComponent(i);
                    if (m.isVisible()) {
                        Dimension d = preferred ? m.getPreferredSize() : m.getMinimumSize();

                        // Wrap line if this component doesn't fit
                        if ((rowWidth + d.width) > maxWidth) {
                            dim.width = Math.max(rowWidth, dim.width);
                            dim.height += rowHeight + vgap;
                            rowWidth = 0;
                            rowHeight = 0;
                        }

                        // Add component size to current row
                        if (rowWidth != 0) {
                            rowWidth += hgap;
                        }
                        rowWidth += d.width;
                        rowHeight = Math.max(rowHeight, d.height);
                    }
                }

                dim.width = Math.max(rowWidth, dim.width);
                dim.height += rowHeight + vgap;
                dim.width += horizontalInsetsAndGap;
                dim.height += insets.top + insets.bottom + vgap * 2;

                // When using a scroll pane or the DecoratedLookAndFeel we need to
                // make sure the preferred size is less than the size of the
                // target containter so shrinking the container size works
                // correctly. Removing the horizontal gap is an easy way to do this.
                Container scrollPane = SwingUtilities.getAncestorOfClass(JScrollPane.class, target);
                if (scrollPane != null && target.isValid()) {
                    dim.width -= (hgap + 1);
                }

                return dim;
            }
        }

    }

    public static void setFlashButtonTrue(){
        flashButton.setSelected(false);
        flashText.setText("自动每5秒刷新表格中");

    }

    public static void setFlashButtonFalse(){
        flashButton.setSelected(true);
        flashText.setText("暂停每5秒刷新表格");
    }

    public static boolean getFlashButtonStatus(){
        // 检查按钮的选中状态
        if (flashButton.isSelected()) {
            // 如果按钮被选中，意味着刷新功能被激活，我们将文本设置为 "暂停刷新中"
            return true;
        } else {
            // 如果按钮没有被选中，意味着刷新功能没有被激活，我们将文本设置为 "自动刷新"
            return false;
        }
    }



}


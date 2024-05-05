package burp.ui;

import burp.*;
import burp.model.TableLogModel;
import burp.model.WeakPassword;
import burp.ui.event.FingerTabEventHandlers;
import burp.ui.renderer.HavingImportantRenderer;
import burp.ui.renderer.HeaderIconRenderer;
import burp.ui.renderer.IconTableCellRenderer;
import burp.util.UiUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;


public class WeakPasswordTab implements IMessageEditorController {
    public static JPanel contentPane;
    private JSplitPane splitPane;
    public static IHttpRequestResponse currentlyDisplayedItem;
    public static JLabel lbRequestCount;
    public static JLabel lbSuccessCount;

    public static IMessageEditor requestViewer;
    public static IMessageEditor responseViewer;
    public static ITextEditor resultDeViewer;

    public static JToggleButton weakPasswordBlasting;
    private static DefaultTableModel model;
    public static JTable table;
    public static JToggleButton flashButton;
    public static JComboBox<String> choicesComboBox;
    public static JLabel flashText;
    public static Timer timer;
    public static LocalDateTime operationStartTime = LocalDateTime.now();

    public WeakPasswordTab() {
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



        // 转发url总数，默认0
        JLabel lbRequest = new JLabel("Total:");
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
        JLabel lbSucces = new JLabel("Weak Password Success:");
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

        // 刷新按钮按钮
        flashButton = new JToggleButton(UiUtils.getImageIcon("/icon/runningButton.png", 24, 24));
        flashButton.setSelectedIcon(UiUtils.getImageIcon("/icon/flashButton.png", 24, 24));
        flashButton.setPreferredSize(new Dimension(30, 30));
        flashButton.setBorder(null);  // 设置无边框
        flashButton.setFocusPainted(false);  // 移除焦点边框
        flashButton.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        flashButton.setToolTipText("用于控制表格是否自动化刷新，还是手工点击刷新");

        // 刷新按钮按钮
        weakPasswordBlasting = new JToggleButton(UiUtils.getImageIcon("/icon/WeakPasswordBlasting.png", 24, 24));
        weakPasswordBlasting.setSelectedIcon(UiUtils.getImageIcon("/icon/WeakPasswordBlastingFalse.png", 24, 24));
        weakPasswordBlasting.setPreferredSize(new Dimension(30, 30));
        weakPasswordBlasting.setBorder(null);  // 设置无边框
        weakPasswordBlasting.setFocusPainted(false);  // 移除焦点边框
        weakPasswordBlasting.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        weakPasswordBlasting.setToolTipText("弱口令爆破开启（功能开发中，请进群敬请期待）");

        weakPasswordBlasting.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 例如，更新FingerConfigTab中的按钮状态
                BurpExtender.getTags().fingerTab.weakPasswordBlasting.setSelected(weakPasswordBlasting.isSelected());
            }
        });

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
                    showFilter();
                }
            }
        });

        // 刷新文本
        flashText = new JLabel("自动每5秒刷新表格中");

        gbc_buttons.gridx = 8; // 将横坐标位置移动到下一个单元格
        FilterPanel.add(weakPasswordBlasting, gbc_buttons);
        gbc_buttons.gridx = 9; // 将横坐标位置移动到下一个单元格
        FilterPanel.add(flashButton, gbc_buttons);
        gbc_buttons.gridx = 10; // 将横坐标位置移动到下一个单元格
        FilterPanel.add(flashText, gbc_buttons);

        // 添加填充以在右侧占位
        GridBagConstraints gbc_rightFiller = new GridBagConstraints();
        gbc_rightFiller.weightx = 1; // 使得这个组件吸收额外的水平空间
        gbc_rightFiller.gridx = 12; // 位置设置为最后一个单元格
        gbc_rightFiller.gridy = 0; // 第一行
        gbc_rightFiller.fill = GridBagConstraints.HORIZONTAL; // 水平填充
        FilterPanel.add(Box.createHorizontalGlue(), gbc_rightFiller);


        // 添加一个 "清除" 按钮
        JButton btnClear = new JButton("清空");
        GridBagConstraints gbc_btnClear = new GridBagConstraints();
        gbc_btnClear.insets = new Insets(0, 0, 0, 5);
        gbc_btnClear.fill = 0;
        gbc_btnClear.gridx = 13;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnClear.gridy = 0;
        FilterPanel.add(btnClear, gbc_btnClear);

        // 给 "清空" 按钮添加一个监听事件
        btnClear.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                BurpExtender.getDataBaseService().clearWeakPasswordTable();
                showFilter();
            }
        });

        // 功能按钮
        JPopupMenu moreMenu = new JPopupMenu("功能");
        JButton moreButton = new JButton();
        moreButton.setIcon(UiUtils.getImageIcon("/icon/moreButton.png", 17, 17));
        GridBagConstraints gbc_btnMore = new GridBagConstraints();
        gbc_btnClear.insets = new Insets(0, 0, 0, 5);
        gbc_btnClear.fill = 0;
        gbc_btnClear.gridx = 14;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnClear.gridy = 0;
        FilterPanel.add(moreButton, gbc_btnMore);


        // 点击”功能“的监听事件
        moreButton.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                moreMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        });

        contentPane.add(topPanel,BorderLayout.NORTH);

        contentPane.add(topPanel,BorderLayout.NORTH);  // 只在 contentPane 的北部添加一个组件

        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setDividerLocation(0.5);
        contentPane.add(splitPane, BorderLayout.CENTER);

        // 数据展示面板
        model = new DefaultTableModel(new Object[]{"#", "url", "finger", "weakPassword", "test_number", "status", "time"}, 0) {
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
        table.getColumnModel().getColumn(1).setMinWidth(300);
        table.getColumnModel().getColumn(2).setMinWidth(60);
        table.getColumnModel().getColumn(3).setMinWidth(180);
        table.getColumnModel().getColumn(4).setMinWidth(60);
        table.getColumnModel().getColumn(5).setMinWidth(60);
        table.getColumnModel().getColumn(6).setMinWidth(60);

        // 创建一个居中对齐的单元格渲染器
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);

        DefaultTableCellRenderer leftRenderer = new DefaultTableCellRenderer();
        leftRenderer.setHorizontalAlignment(JLabel.LEFT);

        table.getColumnModel().getColumn(0).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(1).setCellRenderer(leftRenderer);
        table.getColumnModel().getColumn(2).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(3).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(5).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(6).setCellRenderer(centerRenderer);

        IconTableCellRenderer havingImportantRenderer = new IconTableCellRenderer();
        table.getColumnModel().getColumn(5).setCellRenderer(havingImportantRenderer);

        // 创建右键菜单
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem clearItem = new JMenuItem("清除");
        popupMenu.add(clearItem);
        // 将右键菜单添加到表格
        table.setComponentPopupMenu(popupMenu);


        JScrollPane jspLogTable = new JScrollPane(table);
        splitPane.setTopComponent(jspLogTable);

        // 设置表格选择模式为单行选择
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // 添加ListSelectionListener来监听行选择事件
        table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
           public void valueChanged(ListSelectionEvent event) {
               if (!event.getValueIsAdjusting() && table.getSelectedRow() != -1) {
                   setFlashButtonFalse();
                   operationStartTime = LocalDateTime.now();
                   // 在这里获取选中行的数据
                   int selectedRow = table.getSelectedRow();
                   // 根据您的数据模型结构获取数据
                   String url = model.getValueAt(selectedRow, 1).toString();
                   WeakPassword wp = BurpExtender.getDataBaseService().getWeakPasswordByUrl(url);
                   resultDeViewer.setText(wp.getResultInfo().getBytes());
                   // 例如，你可以将它们设置到一个 HTTP 消息编辑器组件中
                   requestViewer.setMessage(wp.getRequestsByte(), true); // true 表示请求消息
                   responseViewer.setMessage(wp.getResponseByte(), false); // false 表示响应消息

               }
           }
       });


        JTabbedPane tabs = new JTabbedPane();
        requestViewer = BurpExtender.getCallbacks().createMessageEditor(this, false);
        responseViewer = BurpExtender.getCallbacks().createMessageEditor(this, false);
        resultDeViewer = BurpExtender.getCallbacks().createTextEditor();

        tabs.addTab("Result Details", resultDeViewer.getComponent());
        tabs.addTab("Request", requestViewer.getComponent());
        tabs.addTab("Original Response", responseViewer.getComponent());
        splitPane.setBottomComponent(tabs);

        BurpExtender.getCallbacks().customizeUiComponent(topPanel);

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
            lbSuccessCount.setText(Integer.toString(BurpExtender.getDataBaseService().getWeakPasswordSuccessCount()));
            lbRequestCount.setText(Integer.toString(BurpExtender.getDataBaseService().getWeakPasswordCount()));
            // 获取数据库中的所有ApiDataModels
            java.util.List<WeakPassword> weakPasswordList = BurpExtender.getDataBaseService().getAllWeakPassword();

            // 遍历apiDataModelMap
            for (WeakPassword weakPasswordModel : weakPasswordList) {
                model.insertRow(0, new Object[]{
                        weakPasswordModel.getId(),
                        weakPasswordModel.getUrl(),
                        weakPasswordModel.getFinger(),
                        weakPasswordModel.getWeakPassword(),
                        weakPasswordModel.getTestNumber(),
                        weakPasswordModel.getStatus(),
                        weakPasswordModel.getTime()
                });
            }
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


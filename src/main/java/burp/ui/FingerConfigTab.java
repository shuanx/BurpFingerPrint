package burp.ui;

import burp.BurpExtender;
import burp.model.FingerPrintRule;

import java.util.Arrays;
import java.util.List;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableCellEditor;
import javax.swing.table.DefaultTableCellRenderer;
import java.net.URL;
import java.awt.event.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import java.io.File;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.io.FileOutputStream;



public class FingerConfigTab extends JPanel {
    private DefaultTableModel model;
    private JTable table;
    private JDialog editPanel;  // 新增：编辑面板
    private Integer editingRow = null;
    private JTextField cmsField, methodField, locationField, keywordField;  // 新增：编辑面板的文本字段

    public FingerConfigTab() {
        setLayout(new BorderLayout());

        JPanel toolbar = new JPanel();
        toolbar.setLayout(new BorderLayout());
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        // 新增按钮
        JButton addButton = new JButton("新增");
        addButton.setIcon(getImageIcon("/icon/addButtonIcon.png"));
        // 创建一个面板来放置放在最左边的按钮
        leftPanel.add(addButton);
        // 全部按钮
        JButton allButton = new JButton("全部");
        // 检索框
        JTextField searchField = new JTextField(15);
        // 检索按钮
        JButton searchButton = new JButton();
        searchButton.setIcon(getImageIcon("/icon/searchButton.png"));
        searchButton.setToolTipText("搜索");
        // 功能按钮
        JPopupMenu popupMenu = new JPopupMenu("功能");
        JMenuItem importItem = new JMenuItem("导入");
        importItem.setIcon(getImageIcon("/icon/importItem.png"));
        JMenuItem exportItem = new JMenuItem("导出");
        exportItem.setIcon(getImageIcon("/icon/exportItem.png"));
        JMenuItem resetItem = new JMenuItem("重置");
        resetItem.setIcon(getImageIcon("/icon/resetItem.png"));
        popupMenu.add(importItem);
        popupMenu.add(exportItem);
        popupMenu.add(resetItem);
        JButton moreButton = new JButton();
        moreButton.setIcon(getImageIcon("/icon/moreButton.png"));

        // 布局
        rightPanel.add(allButton);
        rightPanel.add(searchField);
        rightPanel.add(searchButton);
        rightPanel.add(moreButton);
        // 将左右面板添加到总的toolbar面板中
        toolbar.add(leftPanel, BorderLayout.WEST);
        toolbar.add(rightPanel, BorderLayout.EAST);
        add(toolbar, BorderLayout.NORTH);


        // 输入”检索区域“的监听事件
        searchField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String searchText = searchField.getText(); // 获取用户输入的搜索文本

                // 清除表格的所有行
                model.setRowCount(0);

                // 重新添加匹配搜索文本的行
                int counter = 1;
                for (FingerPrintRule rule : BurpExtender.fingerprintRules){
                    if (rule.getCms().contains(searchText)) { // 如果 CMS 包含搜索文本
                        model.addRow(new Object[]{
                                counter,
                                rule.getCms(), // 获取cms信息
                                rule.getMethod(), // 获取method信息
                                rule.getLocation(), // 获取location信息
                                String.join(",", rule.getKeyword()),
                                new String[] {"Edit", "Delete"} // 操作按钮
                        });
                        counter ++;
                    }
                }
            }
        });
        searchButton.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                String searchText = searchField.getText(); // 获取用户输入的搜索文本
                // 清除表格的所有行
                model.setRowCount(0);
                // 重新添加匹配搜索文本的行
                int counter = 1;
                for (FingerPrintRule rule : BurpExtender.fingerprintRules){
                    if (rule.getCms().contains(searchText)) { // 如果 CMS 包含搜索文本
                        model.addRow(new Object[]{
                                counter,
                                rule.getCms(), // 获取cms信息
                                rule.getMethod(), // 获取method信息
                                rule.getLocation(), // 获取location信息
                                String.join(",", rule.getKeyword()),
                                new String[] {"Edit", "Delete"} // 操作按钮
                        });
                        counter ++;
                    }
                }
            }
        });
        // 点击“全部“的监听事件
        allButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                // 清除表格的所有行
                model.setRowCount(0);

                // 添加所有的行
                int counter = 1;
                for (FingerPrintRule rule : BurpExtender.fingerprintRules){
                    model.addRow(new Object[]{
                            counter,
                            rule.getCms(), // 获取cms信息
                            rule.getMethod(), // 获取method信息
                            rule.getLocation(), // 获取location信息
                            String.join(",", rule.getKeyword()),
                            new String[] {"Edit", "Delete"} // 操作按钮
                    });
                    counter ++;
                }
            }
        });
        // 点击“新增”的监听事件
        addButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清空编辑面板的文本字段
                cmsField.setText("");
                methodField.setText("");
                locationField.setText("");
                keywordField.setText("");

                // 设置编辑面板的位置并显示
                Point locationOnScreen = ((Component)e.getSource()).getLocationOnScreen();
                editPanel.setLocation(locationOnScreen.x + 70, locationOnScreen.y);  // 设置编辑面板的位置
                editPanel.setVisible(true);  // 显示编辑面板
            }
        });
        // 点击”功能“的监听事件
        moreButton.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                popupMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        });
        // 点击导出按钮
        exportItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                List<FingerPrintRule> rulesToExport = BurpExtender.fingerprintRules;

                // 将数据转换为JSON格式
                Gson gson = new GsonBuilder().setPrettyPrinting().create();
                String json = gson.toJson(rulesToExport);

                // 弹出文件选择对话框，让用户选择保存位置
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("保存为");
                fileChooser.setFileFilter(new FileNameExtensionFilter("JSON文件 (*.json)", "json"));
                int userSelection = fileChooser.showSaveDialog(FingerConfigTab.this);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File fileToSave = fileChooser.getSelectedFile();
                    // 确保文件有.json扩展名
                    if (!fileToSave.getAbsolutePath().endsWith(".json")) {
                        fileToSave = new File(fileToSave + ".json");
                    }

                    try {
                        // 使用UTF-8编码写入文件
                        OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(fileToSave), StandardCharsets.UTF_8);
                        writer.write(json);
                        writer.close();

                        JOptionPane.showMessageDialog(FingerConfigTab.this, "数据已导出至: " + fileToSave.getAbsolutePath(), "导出成功", JOptionPane.INFORMATION_MESSAGE);
                    } catch (IOException ex) {
                        JOptionPane.showMessageDialog(FingerConfigTab.this, "写入文件时发生错误: " + ex.getMessage(), "导出失败", JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        });
        // 点击导入按钮
        // 点击重置按钮


        // 表格数据
        model = new DefaultTableModel(new Object[]{"#", "CMS", "Method", "location", "keyword", "Action"}, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                switch (columnIndex) {
                    case 3:
                        return JButton.class;
                    default:
                        return super.getColumnClass(columnIndex);
                }
            }
        };
        int counter = 1;
        for (FingerPrintRule rule : BurpExtender.fingerprintRules){
            model.addRow(new Object[]{
                    counter,
                    rule.getCms(), // 获取cms信息
                    rule.getMethod(), // 获取method信息
                    rule.getLocation(), // 获取location信息
                    String.join(",", rule.getKeyword()),
                    new String[] {"Edit", "Delete"} // 操作按钮
            });
            counter ++;

        }


        table = new JTable(model);
        CenterRenderer centerRenderer = new CenterRenderer();
        table.getColumnModel().getColumn(0).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(1).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(2).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(3).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);
        // 设置操作列的宽度以适应两个按钮
        int actionColumnWidth = 100;  // 假设每个按钮宽度为70，中间间隔10
        table.getColumnModel().getColumn(5).setPreferredWidth(actionColumnWidth);
        table.getColumnModel().getColumn(5).setMaxWidth(actionColumnWidth);
        table.getColumnModel().getColumn(5).setCellRenderer(new ButtonRenderer());
        table.getColumnModel().getColumn(5).setCellEditor(new ButtonEditor(table));

        add(new JScrollPane(table), BorderLayout.CENTER);

        // 编辑页面框
        editPanel = new JDialog();
        editPanel.setTitle("新增指纹");
        editPanel.setLayout(new GridBagLayout());  // 更改为 GridBagLayout
        editPanel.setSize(500, 200);
        editPanel.setDefaultCloseOperation(JDialog.HIDE_ON_CLOSE);
        editPanel.setModal(false);
        editPanel.setResizable(true);

        cmsField = new JTextField();
        methodField = new JTextField();
        locationField = new JTextField();
        keywordField = new JTextField();

        // 创建 GridBagConstraints 对象来控制每个组件的布局
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.WEST;  // 紧靠左边
        constraints.fill = GridBagConstraints.HORIZONTAL;  // 水平填充
        constraints.insets = new Insets(10, 10, 10, 10);  // 设置内边距为10像素

        // 添加 "CMS" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 0;  // 在网格的第一行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editPanel.add(new JLabel("CMS:"), constraints);

        // 添加 "CMS" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editPanel.add(cmsField, constraints);

        // 添加 "Method" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 1;  // 在网格的第二行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editPanel.add(new JLabel("Method:"), constraints);

        // 添加 "Method" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editPanel.add(methodField, constraints);

        // 添加 "Location" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 2;  // 在网格的第三行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editPanel.add(new JLabel("Location:"), constraints);

        // 添加 "Location" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editPanel.add(locationField, constraints);

        // 添加 "Keyword" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 3;  // 在网格的第四行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editPanel.add(new JLabel("Keyword:"), constraints);

        // 添加 "Keyword" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editPanel.add(keywordField, constraints);

        // 根据需要，为 Location 和 Keyword 输入框设置首选大小
        cmsField.setPreferredSize(new Dimension(100, cmsField.getPreferredSize().height));
        methodField.setPreferredSize(new Dimension(100, methodField.getPreferredSize().height));
        locationField.setPreferredSize(new Dimension(100, locationField.getPreferredSize().height));
        keywordField.setPreferredSize(new Dimension(100, keywordField.getPreferredSize().height));


        JButton saveButton = new JButton("Save");
        saveButton.setIcon(getImageIcon("/icon/saveButton.png"));

        // 修改保存按钮的点击事件监听器
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 获取用户输入的数据
                String cms = cmsField.getText();
                String method = methodField.getText();
                String location = locationField.getText();
                List<String> keyword = Arrays.asList(keywordField.getText().split(","));

                // 检查输入框是否都不为空
                if (cms.trim().isEmpty() || method.trim().isEmpty() ||
                        location.trim().isEmpty() ||  keyword.stream().allMatch(String::isEmpty)) {
                    // 显示错误消息
                    JOptionPane.showMessageDialog(editPanel,
                            "所有输入框都必须填写。",
                            "输入错误",
                            JOptionPane.ERROR_MESSAGE);
                    return; // 不再继续执行后面的代码
                }

                if (editingRow != null) {
                    // 如果是编辑现有规则，更新数据源和表格模型中的数据
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(editingRow);
                    rule.setCms(cms);
                    rule.setMethod(method);
                    rule.setLocation(location);
                    rule.setKeyword(keyword);

                    model.setValueAt(cms, editingRow, 1);
                    model.setValueAt(method, editingRow, 2);
                    model.setValueAt(location, editingRow, 3);
                    model.setValueAt(String.join(",", keyword), editingRow, 4);

                    // 重置当前编辑行为null
                    editingRow = null;
                } else {
                    // 如果是添加新规则，创建新的 FingerPrintRule 并添加到列表和表格模型中
                    FingerPrintRule newRule = new FingerPrintRule(cms, method, location, keyword);
                    BurpExtender.fingerprintRules.add(newRule);
                    model.addRow(new Object[]{
                            BurpExtender.fingerprintRules.size(),
                            newRule.getCms(),
                            newRule.getMethod(),
                            newRule.getLocation(),
                            String.join(",", newRule.getKeyword()),
                            new String[]{"Edit", "Delete"}
                    });
                }

                // 隐藏编辑面板
                editPanel.setVisible(false);
            }
        });
        editPanel.add(saveButton);


    }

    public ImageIcon getImageIcon(String iconPath){
        // 根据按钮的大小缩放图标
        URL iconURL = getClass().getResource(iconPath);
        ImageIcon originalIcon = new ImageIcon(iconURL);
        Image img = originalIcon.getImage();
        Image newImg = img.getScaledInstance(17, 17, Image.SCALE_SMOOTH);
        return new ImageIcon(newImg);
    }

    class ButtonRenderer extends JPanel implements TableCellRenderer {
        private final JButton editButton;
        private final JButton deleteButton;

        public ButtonRenderer() {
            setBorder(BorderFactory.createLineBorder(Color.BLACK));
            setLayout(new FlowLayout(FlowLayout.CENTER, 5, 0));
            editButton = new JButton();
            editButton.setIcon(getImageIcon("/icon/editButton.png"));
            deleteButton = new JButton();
            deleteButton.setIcon(getImageIcon("/icon/deleteButton.png"));

            editButton.setPreferredSize(new Dimension(40, 20));
            deleteButton.setPreferredSize(new Dimension(40, 20));

            add(editButton);
            add(deleteButton);
            setBorder(BorderFactory.createEmptyBorder());
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            if (isSelected) {
                setBackground(table.getSelectionBackground());
            } else {
                setBackground(table.getBackground());
            }
            return this;
        }
    }

    class ButtonEditor extends AbstractCellEditor implements TableCellEditor {
        private final JPanel panel;
        private final JButton editButton;
        private final JButton deleteButton;
        private JTable table;
        private int row;

        public ButtonEditor(JTable table) {
            this.table = table;
            panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 0));
            editButton = new JButton();
            editButton.setIcon(getImageIcon("/icon/editButton.png"));
            deleteButton = new JButton();
            deleteButton.setIcon(getImageIcon("/icon/deleteButton.png"));

            editButton.setPreferredSize(new Dimension(40, 20));
            deleteButton.setPreferredSize(new Dimension(40, 20));

            editButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    // 编辑按钮的逻辑
                    int modelRow = table.convertRowIndexToModel(row);
                    editingRow = modelRow; // 保存当前编辑的行索引
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(modelRow);
                    cmsField.setText(rule.getCms());
                    methodField.setText(rule.getMethod());
                    locationField.setText(rule.getLocation());
                    keywordField.setText(String.join(",", rule.getKeyword()));

                    // 显示编辑面板
                    Point btnLocation = ((JButton)e.getSource()).getLocationOnScreen();
                    editPanel.setLocation(btnLocation.x - editPanel.getWidth() / 2, btnLocation.y + ((JButton)e.getSource()).getHeight());

                    editPanel.setVisible(true);
                    fireEditingStopped();
                }
            });

            deleteButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    fireEditingStopped(); // 确保停止编辑状态
                    int modelRow = table.convertRowIndexToModel(row);
                    BurpExtender.fingerprintRules.remove(modelRow); // 删除数据源中的数据
                    ((DefaultTableModel) table.getModel()).removeRow(modelRow); // 删除表格模型中的数据

                    // 在删除行之后，重新验证和重绘表格
                    table.revalidate();
                    table.repaint();
                }
            });

            panel.add(editButton);
            panel.add(deleteButton);
            panel.setBorder(BorderFactory.createEmptyBorder());
        }

        @Override
        public Object getCellEditorValue() {
            return null;
        }

        @Override
        public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
            this.row = table.convertRowIndexToModel(row); // 转换为模型索引，以防有排序
            return panel;
        }
    }



    class CenterRenderer extends DefaultTableCellRenderer {
        public CenterRenderer() {
            setHorizontalAlignment(JLabel.CENTER);
        }
    }
}
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
import javax.swing.event.*;



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
        int actionColumnWidth = 200;  // 假设每个按钮宽度为70，中间间隔10
        table.getColumnModel().getColumn(5).setPreferredWidth(actionColumnWidth);
        table.getColumnModel().getColumn(5).setMaxWidth(actionColumnWidth);
        table.getColumnModel().getColumn(5).setCellRenderer(new ButtonRenderer());
        table.getColumnModel().getColumn(5).setCellEditor(new ButtonEditor(table));

        add(new JScrollPane(table), BorderLayout.CENTER);

        // 编辑页面框
        editPanel = new JDialog();
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
        constraints.weightx = 1.0;  // 水平扩展的权重为1
        constraints.insets = new Insets(10, 10, 10, 10);  // 设置内边距为10像素

        // 添加 "CMS" 标签和文本字段
        constraints.gridx = 0;  // 在网格的第一列添加组件（索引从0开始）
        constraints.gridy = 0;  // 在网格的第一行添加组件
        editPanel.add(new JLabel("CMS:"), constraints);
        constraints.gridx = 1;  // 在网格的第二列添加组件
        editPanel.add(cmsField, constraints);

        // 添加 "Method" 标签和文本字段
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 1;  // 在网格的第二行添加组件
        editPanel.add(new JLabel("Method:"), constraints);
        constraints.gridx = 1;  // 在网格的第二列添加组件
        editPanel.add(methodField, constraints);

        // 添加 "Location" 标签和文本字段
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 2;  // 在网格的第三行添加组件
        editPanel.add(new JLabel("Location:"), constraints);
        constraints.gridx = 1;  // 在网格的第二列添加组件
        editPanel.add(locationField, constraints);

        // 添加 "Keyword" 标签和文本字段
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 3;  // 在网格的第四行添加组件
        editPanel.add(new JLabel("Keyword:"), constraints);
        constraints.gridx = 1;  // 在网格的第二列添加组件
        editPanel.add(keywordField, constraints);




        JButton saveButton = new JButton("Save");

        // 修改保存按钮的点击事件监听器
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 获取用户输入的数据
                String cms = cmsField.getText();
                String method = methodField.getText();
                String location = locationField.getText();
                List<String> keyword = Arrays.asList(keywordField.getText().split(","));

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

            editButton.setPreferredSize(new Dimension(70, 20));
            deleteButton.setPreferredSize(new Dimension(70, 20));

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

            editButton.setPreferredSize(new Dimension(70, 20));
            deleteButton.setPreferredSize(new Dimension(70, 20));

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
                    // 删除按钮的逻辑
                    int modelRow = table.convertRowIndexToModel(row);
                    BurpExtender.fingerprintRules.remove(modelRow);  // 从数据源中删除
                    ((DefaultTableModel)table.getModel()).removeRow(modelRow); // 从表格视图中删除

                    fireEditingStopped(); // 结束编辑状态
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
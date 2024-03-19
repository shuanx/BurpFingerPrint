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
import java.util.ArrayList;
import java.util.Arrays;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableCellEditor;
import javax.swing.table.DefaultTableCellRenderer;



public class FingerConfigTab extends JPanel {
    private DefaultTableModel model;
    private JTable table;
    private JDialog editPanel;  // 新增：编辑面板
    private JTextField cmsField, methodField, locationField, keywordField;  // 新增：编辑面板的文本字段

    public FingerConfigTab() {
        setLayout(new BorderLayout());


        // Create the toolbar panel
        JPanel toolbar = new JPanel();

        // 在工具栏上添加一个“新增”按钮
        JButton addButton = new JButton("新增");
        toolbar.add(addButton, 0); // 将按钮添加到工具栏的最左边

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

        toolbar.setLayout(new FlowLayout(FlowLayout.RIGHT));
        JButton allButton = new JButton("全部");
        toolbar.add(allButton);



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


//        JButton focusButton = new JButton("重点指纹");
//        toolbar.add(focusButton);
        JTextField searchField = new JTextField(15);
        toolbar.add(searchField);

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
                                rule.getKeyword(),
                                new String[] {"Edit", "Delete"} // 操作按钮
                        });
                        counter ++;
                    }
                }
            }
        });


        add(toolbar, BorderLayout.NORTH);

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
//        table.getColumnModel().getColumn(5).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(5).setCellRenderer(new ButtonRenderer());

        add(new JScrollPane(table), BorderLayout.CENTER);

        table.getColumnModel().getColumn(5).setCellRenderer(new ButtonRenderer());
        table.getColumnModel().getColumn(5).setCellEditor(new ButtonEditor());

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

                // 创建新的 FingerPrintRule 并添加到列表中
                FingerPrintRule rule = new FingerPrintRule(cms, method, location, keyword);
                BurpExtender.fingerprintRules.add(rule);

                // 在表格中添加一行新的数据
                model.addRow(new Object[]{
                        BurpExtender.fingerprintRules.size(),
                        rule.getCms(),
                        rule.getMethod(),
                        rule.getLocation(),
                        String.join(",", rule.getKeyword()),
                        new String[] {"Edit", "Delete"}
                });

                // 隐藏编辑面板
                editPanel.setVisible(false);
            }
        });
        editPanel.add(saveButton);


    }

    class ButtonRenderer implements TableCellRenderer {
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            JPanel panel = new JPanel();
            panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
            if (value instanceof String[]) {
                for (String text : (String[]) value) {
                    JButton button = new JButton(text);
                    button.setPreferredSize(new Dimension(70, 30));
                    panel.add(button);
                }
            }
            return panel;
        }
    }

    class ButtonEditor extends AbstractCellEditor implements TableCellEditor {
        private JPanel panel;
        private String label;
        private int row;

        public ButtonEditor() {
            panel = new JPanel();
            panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
            JButton editButton = new JButton("Edit");
            editButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    label = "Edit";
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(row);

                    cmsField.setText(rule.getCms());
                    methodField.setText(rule.getMethod());
                    locationField.setText(rule.getLocation());
                    keywordField.setText(String.join(",", rule.getKeyword()));

                    // 设置编辑面板的位置并显示
                    Point locationOnScreen = ((Component)e.getSource()).getLocationOnScreen();
                    editPanel.setLocation(locationOnScreen.x + 70, locationOnScreen.y);  // 设置编辑面板的位置
                    editPanel.setVisible(true);  // 显示编辑面板


                    fireEditingStopped();
                }




            });
            panel.add(editButton);
            JButton deleteButton = new JButton("Delete");
            deleteButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    label = "Delete";
                    fireEditingStopped();
                }
            });
            panel.add(deleteButton);
        }

        public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
            this.row = row; // 记住当前行
            return panel;
        }

        public Object getCellEditorValue() {
            if (label.equals("Delete")) {
                // 删除相应的 FingerPrintRule
                BurpExtender.fingerprintRules.remove(row);

                // 从表格中删除该行
                model.removeRow(row);

                // 注意：如果你的 FingerPrintRule 列表是从某个持久化的地方（如文件或数据库）加载的，你需要同步更新那个地方的数据
            }
            return new String[] {"Edit", "Delete"};
        }
    }

    class CenterRenderer extends DefaultTableCellRenderer {
        public CenterRenderer() {
            setHorizontalAlignment(JLabel.CENTER);
        }
    }
}
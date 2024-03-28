package burp.ui.event;

import burp.BurpExtender;
import burp.ui.FingerConfigTab;
import burp.ui.FingerTab;
import burp.ui.HttpLogTable;
import burp.ui.HttpLogTableModel;
import burp.util.UiUtils;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.*;
import java.util.List;

/**
 * @author： shaun
 * @create： 2024/3/27 21:41
 * @description：TODO
 */
public class FingerTabEventHandlers {
    public static MouseAdapter headerAddMouseListener(HttpLogTable logTable) {
        return new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (logTable.getColumnModel().getColumnIndexAtX(e.getX()) == 6) { // 假设类型列的索引是1
                    JPopupMenu filterMenu = new JPopupMenu();

                    // “全部”选项用于移除过滤
                    JMenuItem allItem = new JMenuItem("全部");
                    allItem.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            filterTableByType(null); // 移除过滤，显示全部
                        }
                    });
                    filterMenu.add(allItem);

                    filterMenu.add(new JSeparator()); // 分隔线

                    // 为每个独特的类型创建菜单项
                    for (String type : BurpExtender.tags.fingerConfigTab.uniqueTypes) {
                        JMenuItem menuItem = new JMenuItem(type);
                        menuItem.addActionListener(new ActionListener() {
                            @Override
                            public void actionPerformed(ActionEvent e) {
                                filterTableByType(type); // 根据选中的类型过滤表格
                            }
                        });
                        filterMenu.add(menuItem);
                    }

                    filterMenu.show(e.getComponent(), e.getX(), e.getY()); // 显示菜单
                }
            }

            private void filterTableByType(String type) {
                TableRowSorter<TableModel> sorter = new TableRowSorter<>((TableModel) logTable.getModel());
                logTable.setRowSorter(sorter);

                if (type == null || type.equals("全部")) {
                    // 显示所有行
                    sorter.setRowFilter(null);
                } else {
                    // 只显示type列符合条件的行
                    sorter.setRowFilter(RowFilter.regexFilter(type, 6)); // 假设类型列的索引是1
                }
            }
        };
    }


    public static TableModelListener modelAddTableModelListener(HttpLogTableModel model, JPanel tagsPanel, HashMap<String, JLabel> resultMap, HttpLogTable logTable) {
        return new TableModelListener() {
            private static final int MAX_LABEL = 20;
            private List<String> labelList = new ArrayList<>(); // 用来存储标签文本的列表
            private JLabel ellipsisLabel = new JLabel("..."); // 省略号标签
            @Override
            public void tableChanged(TableModelEvent e) {
                HashMap<String, Integer> resultCounts = new HashMap<>();
                // 遍历表格中所有行
                for (int i = 0; i < model.getRowCount(); i++) {
                    String result = (String) model.getValueAt(i, 5); // 获取结果值
                    String[] parts = result.split(", "); // 根据", "进行切分
                    for (String part : parts) {
                        resultCounts.put(part, resultCounts.getOrDefault(part, 0) + 1); // 添加到映射中进行去重，并计数
                    }
                }
                clearAllResultLabels(tagsPanel);

                // 创建一个 TreeMap 并进行反向排序
                TreeMap<Integer, LinkedList<String>> sortedResults = new TreeMap<>(Collections.reverseOrder());
                for (Map.Entry<String, Integer> entry : resultCounts.entrySet()) {
                    sortedResults.computeIfAbsent(entry.getValue(), k -> new LinkedList<>()).add(entry.getKey());
                }

                // 添加新的结果标签
                List<String> tmplabelList = new ArrayList<>(); // 用来存储标签文本的列表
                for (Map.Entry<Integer, LinkedList<String>> entry : sortedResults.entrySet()) {
                    Integer count = entry.getKey();
                    for (String result : entry.getValue()) {
                        if(tmplabelList.size() == MAX_LABEL){
                            tmplabelList.add("...");
                            continue;
                        }
                        if(tmplabelList.size() > MAX_LABEL){
                            continue;
                        }
                        tmplabelList.add(result + " (" + count + ")");
                    }
                }
            }

            public void addNewResultLabel(String result, HttpLogTableModel model) {
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



        };
    }


    public static ActionListener btnClearAddActionListener(HttpLogTableModel model, JLabel lbRequestCount, JLabel lbSuccessCount, JPanel tagsPanel){
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清除表格数据
                lbRequestCount.setText("0");
                lbSuccessCount.setText("0");
                model.setRowCount();
                BurpExtender.hasScanDomainSet = new HashSet<>();
                clearAllResultLabels(tagsPanel);
            }
        };
    }


    public static ActionListener exportItemAddActionListener(JPanel contentPane, HttpLogTable logTable){
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Specify a file to save");

                // 设置默认文件名
                fileChooser.setSelectedFile(new File("ExportedData.xlsx"));

                // 限制文件类型为.xlsx
                FileNameExtensionFilter filter = new FileNameExtensionFilter("Excel Files", "xlsx");
                fileChooser.setFileFilter(filter);

                int userSelection = fileChooser.showSaveDialog(contentPane);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File fileToSave = fileChooser.getSelectedFile();
                    // 确保文件有正确的扩展名
                    if (!fileToSave.toString().toLowerCase().endsWith(".xlsx")) {
                        fileToSave = new File(fileToSave.toString() + ".xlsx");
                    }
                    // 导出表格数据到Excel文件
                    UiUtils.exportTableToExcel(fileToSave, contentPane, logTable);
                }
            }
        };
    }


    public static ActionListener clearItemAddActionListener(HttpLogTableModel model, HttpLogTable logTable, JLabel lbSuccessCount){
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int successRequestsCount = Integer.parseInt(lbSuccessCount.getText()) - logTable.getSelectedRows().length;
                lbSuccessCount.setText(Integer.toString(successRequestsCount));
                model.removeSelectedRows(logTable);
            }
        };
    }


    public static ActionListener allFingerprintsButtonAddActionListener(HttpLogTable logTable, JToggleButton allFingerprintsButton){
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 检查按钮状态并切换
                if (allFingerprintsButton.isSelected() && logTable != null) {
                    // 按钮选中状态，应用过滤器以仅显示 isImportant 列为 true 的行
                    RowFilter<TableModel, Integer> importanceFilter = new RowFilter<TableModel, Integer>() {
                        @Override
                        public boolean include(Entry<? extends TableModel, ? extends Integer> entry) {
                            // 假设 isImportant 是第7列（注意列索引从0开始计数）
                            Boolean isImportant = (Boolean) entry.getValue(7); // 根据您的表格实际的列索引来调整
                            return isImportant != null && isImportant;
                        }
                    };
                    ((TableRowSorter<TableModel>) logTable.getRowSorter()).setRowFilter(importanceFilter);
                } else if (logTable != null) {
                    // 按钮未选中状态，移除过滤器以显示所有行
                    ((TableRowSorter<TableModel>) logTable.getRowSorter()).setRowFilter(null);
                }
                // 更新FingerConfigTab中的按钮状态
                FingerConfigTab.allFingerprintsButton.setSelected(allFingerprintsButton.isSelected());
                // 调用FingerConfigTab中的toggleFingerprintsDisplay方法
                FingerConfigTab.toggleFingerprintsDisplay(false, allFingerprintsButton.isSelected());
            }
        };
    }

    public static void clearAllResultLabels(JPanel tagsPanel) {
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